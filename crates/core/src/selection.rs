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
//! State and city names compare ASCII-case-insensitively (user-typed
//! prose against catalog casing); server and gateway names compare
//! exactly. Country codes are ISO 3166-1 alpha-2 and must arrive
//! uppercase — canonicalization is the calling surface's job, and this
//! module refuses anything non-canonical rather than approximating.
//!
//! Non-goal: NetShield level is a per-session feature REQUEST carried
//! to the tunnel (PRD §11.4), never a server filter — this module has
//! no NetShield constraint variant by design; the requested-vs-applied
//! reconciliation is the connection surface's (U6).

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use protonwire_store::catalog::LogicalServer;

/// Latency observations keyed by logical server ID — the caller-supplied
/// probe results (milestone 3 PR-3 wires the bounded on-demand prober;
/// FR-18 forbids full-catalog scans, so keys cover at most a shortlist).
pub type LatencyTable = BTreeMap<String, Duration>;

/// The forbidden throughput ranking signals (the connection-groups
/// yaml contract's `forbidden_ranking_signals`, plus `speed` itself —
/// FR-19's named offender). Rejecting these is T-1's "every input
/// schema" clause for this module's schema.
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

    /// Every signal disabled — the base for callers composing a
    /// partial weight set by hand.
    pub const DEFAULT_ZEROED: Self = Self {
        load: 0.0,
        latency: 0.0,
        stability: 0.0,
        feature_match: 0.0,
        history: 0.0,
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

    /// Whether every weight is finite and non-negative — a hand-built
    /// struct bypassed [`Self::from_pairs`], so `select` re-checks (a
    /// NaN would poison every comparison silently).
    fn is_valid(&self) -> bool {
        [
            self.load,
            self.latency,
            self.stability,
            self.feature_match,
            self.history,
        ]
        .iter()
        .all(|w| w.is_finite() && *w >= 0.0)
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
    /// Per-server port-forwarding CAPABILITY, by logical id (Codex
    /// PR#5 round 4, P1 / FR-87: entitlement is account permission,
    /// NOT server capability — the catalog exposes no PF bit upstream,
    /// so the caller supplies the capability set it composed (the
    /// daemon's PR-4/M6 wiring; official sources provision PF on a
    /// server subset). `None`: capability not composed — a
    /// port-forwarding constraint refuses typed, never
    /// entitled-⇒-every-server. An empty set is a composed "no server
    /// is capable" answer (the request then finds no survivor — the
    /// honest FR-87 outcome).
    pub port_forwarding_capable: Option<std::collections::BTreeSet<String>>,
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
    /// Every stage paired with its report label, in evaluation order
    /// (FR-23P's hard-filter prefix, then the policy stages). The one
    /// table [`Self::ordinal`], [`Self::label`], and the report's
    /// stage list all derive from, so a stage is added in exactly one
    /// place and the order/label pairings can never drift apart. A
    /// candidate is charged to the FIRST stage that eliminates it; the
    /// report renders in this order.
    const STAGES: &[(FilterStage, &'static str)] = &[
        (FilterStage::UnknownStatus, "unknown-status"),
        (FilterStage::Offline, "offline"),
        (FilterStage::AllPhysicalsOffline, "all-physicals-offline"),
        (FilterStage::AbsentFromCatalog, "absent-from-catalog"),
        (FilterStage::ServerType, "server-type"),
        (FilterStage::TargetGeography, "target-geography"),
        (
            FilterStage::PhysicalCountryExclusion,
            "physical-country-exclusion",
        ),
        (FilterStage::ExcludedCountry, "excluded-country"),
        (FilterStage::ExcludedState, "excluded-state"),
        (FilterStage::ExcludedCity, "excluded-city"),
        (FilterStage::ExcludedServer, "excluded-server"),
        (FilterStage::RequiredFeatures, "required-features"),
        (FilterStage::ProtocolCompatibility, "protocol-compatibility"),
        (FilterStage::LoadNotExposed, "load-not-exposed"),
        (FilterStage::NoLatencyObservation, "no-latency-observation"),
    ];

    /// The stage's position in the evaluation order.
    fn ordinal(self) -> usize {
        Self::STAGES
            .iter()
            .position(|(stage, _)| *stage == self)
            .expect("every stage is in STAGES")
    }

    /// The stage's report label.
    fn label(self) -> &'static str {
        Self::STAGES
            .iter()
            .find(|(stage, _)| *stage == self)
            .map(|(_, label)| *label)
            .expect("every stage is in STAGES")
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

    /// Charges `count` eliminations to `stage` and reduces the survivor
    /// count — the policy stages run after the hard filters and report
    /// through the same accounting (FR-22).
    fn charge(&mut self, stage: FilterStage, count: usize) {
        if count == 0 {
            return;
        }
        for (slot, tally) in &mut self.stages {
            if *slot == stage {
                *tally += count;
                break;
            }
        }
        self.survivors -= count;
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

impl ScoringSignals {
    /// The provenance a non-balanced policy reports: what the catalog
    /// exposed and nothing else — no observed latency (only `balanced`
    /// consumes the latency table today) and no weighted breakdown
    /// (only `balanced` carries one).
    fn catalog_only(server: &LogicalServer) -> Self {
        Self {
            proton_score: server.score,
            load: server.load,
            latency: None,
            weighted: None,
        }
    }
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
    /// A port-forwarding constraint reached the core entitled but
    /// WITHOUT the per-server capability data FR-87 requires (Codex
    /// PR#5 round 4, P1: entitlement is account permission, not
    /// server capability — the pre-fix arm treated entitled as
    /// every-server-capable and could select a server that cannot
    /// provide the feature). The caller must compose the capability
    /// set (the catalog exposes no PF bit upstream).
    #[error(
        "port-forwarding capability data unavailable: the account is entitled but no \
         per-server capability set was supplied — supply SelectionContext.port_forwarding_capable \
         (FR-87: only servers that support port forwarding may be selected)"
    )]
    PortForwardingCapabilityUnavailable,
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
    /// A Standard-fleet target combined with the `secure-core` FEATURE
    /// constraint — unsatisfiable BY CONSTRUCTION (Codex PR#5, P1: the
    /// type stage removes every Secure Core logical, the feature stage
    /// then removes every Standard one). Secure Core connectivity is a
    /// TARGET (the routed form, milestone 3 PR-3), never a
    /// Standard-fleet feature filter; the contradiction is refused at
    /// validation with this error rather than the pipeline's
    /// all-stages-empty report.
    #[error(
        "unsatisfiable request: a Standard-fleet target cannot require the `secure-core` \
         feature — Secure Core connectivity is a routed TARGET (milestone 3 PR-3), \
         not a Standard-fleet feature filter"
    )]
    StandardFleetFeatureContradiction,
}

impl Target {
    /// Whether this target names specific logicals (exact match, no
    /// fallback per FR-23) rather than a filtered set.
    fn is_exact(&self) -> bool {
        matches!(self, Target::Server(_) | Target::Gateway(_))
    }

    /// The exact name, when [`Self::is_exact`].
    fn exact_name(&self) -> Option<&str> {
        match self {
            Target::Server(name) | Target::Gateway(name) => Some(name),
            _ => None,
        }
    }

    /// Whether `server` is this target's exact match — the ONE
    /// predicate behind both the type-geography filter
    /// ([`target_stage`]) and the exact-refusal diagnosis
    /// ([`filter_candidates`]), so the filter and the error it reports
    /// can never disagree about what the request named (the drift the
    /// M3 U1 review's P2 fix introduced the second copy of).
    fn matches_exact(&self, server: &LogicalServer) -> bool {
        match self {
            Target::Server(name) => server.name == *name,
            Target::Gateway(name) => server.gateway_name.as_deref() == Some(name.as_str()),
            _ => false,
        }
    }
}

/// ISO 3166-1 alpha-2, uppercase. Canonicalizing user input is the
/// calling surface's job; the pure core refuses non-canonical input
/// rather than approximating it (see the module docs).
fn validate_country(code: &str) -> Result<(), SelectionError> {
    if code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(SelectionError::InvalidCountry(code.to_owned()))
    }
}

/// Validates every country input on the request (FR-20/FR-21/FR-23Q)
/// before any candidate work.
fn validate_request_countries(request: &SelectionRequest) -> Result<(), SelectionError> {
    if let Target::Country(code) = &request.target {
        validate_country(code)?;
    }
    for code in &request.constraints.excluded_countries {
        validate_country(code)?;
    }
    if let Some(code) = &request.constraints.physical_country {
        validate_country(code)?;
    }
    Ok(())
}

/// ASCII-case-insensitive equality for user-typed prose against
/// catalog casing (non-ASCII bytes compare exactly — deterministic).
fn eq_fold(value: Option<&str>, wanted: &str) -> bool {
    value.is_some_and(|v| v.eq_ignore_ascii_case(wanted))
}

/// Whether the logical belongs to the Standard fleet for type-filtered
/// targets (FR-23L: Fastest means the eligible Standard target; gateway
/// and Secure Core are other connection types). Tor/P2P/streaming are
/// Standard-fleet capabilities, not types.
fn is_standard_fleet(server: &LogicalServer) -> bool {
    !server.is_gateway() && !server.is_secure_core_route() && !server.features.secure_core()
}

/// The online-state stage: unknown is never online (FR-13B,
/// fail-closed), offline is offline, and an online logical needs at
/// least one online physical to be connectable.
fn online_stage(server: &LogicalServer) -> Option<FilterStage> {
    match server.status {
        None => Some(FilterStage::UnknownStatus),
        Some(0) => Some(FilterStage::Offline),
        Some(1) => {
            if server.servers.iter().any(|p| p.is_online()) {
                None
            } else {
                Some(FilterStage::AllPhysicalsOffline)
            }
        }
        // The S6 parse enforces the recorded 0/1 domain before any
        // candidate is ever seen here.
        _ => unreachable!("logical Status outside the recorded 0/1 domain"),
    }
}

/// The target geography/type stage. Exact targets match identity here;
/// filtered targets require the Standard fleet, then geography
/// (FR-23L/FR-20). Host-country (smart routing) is reported metadata,
/// never a match key — the exit country is the canonical selector.
fn target_stage(server: &LogicalServer, target: &Target) -> Option<FilterStage> {
    if target.is_exact() {
        return (!target.matches_exact(server)).then_some(FilterStage::TargetGeography);
    }
    if !is_standard_fleet(server) {
        return Some(FilterStage::ServerType);
    }
    let miss = match target {
        Target::Fastest => false,
        Target::Country(code) => server.exit_country != *code,
        Target::State(name) => !eq_fold(server.state.as_deref(), name),
        Target::City(name) => !eq_fold(server.city.as_deref(), name),
        Target::Server(_) | Target::Gateway(_) => unreachable!("handled above"),
    };
    miss.then_some(FilterStage::TargetGeography)
}

/// The physical-country exclusion stage (FR-23Q): exit country equals
/// the known physical country.
fn physical_country_stage(
    server: &LogicalServer,
    constraints: &Constraints,
) -> Option<FilterStage> {
    constraints
        .exclude_physical_country
        .then(|| {
            constraints
                .physical_country
                .as_deref()
                .filter(|cc| **cc == server.exit_country)
                .map(|_| FilterStage::PhysicalCountryExclusion)
        })
        .flatten()
}

/// The explicit user exclusions (FR-21/FR-21A) — the same hard-filter
/// stage as country exclusion, applied to Fastest too.
fn exclusion_stage(server: &LogicalServer, constraints: &Constraints) -> Option<FilterStage> {
    if constraints
        .excluded_countries
        .contains(&server.exit_country)
    {
        return Some(FilterStage::ExcludedCountry);
    }
    if constraints
        .excluded_states
        .iter()
        .any(|name| eq_fold(server.state.as_deref(), name))
    {
        return Some(FilterStage::ExcludedState);
    }
    if constraints
        .excluded_cities
        .iter()
        .any(|name| eq_fold(server.city.as_deref(), name))
    {
        return Some(FilterStage::ExcludedCity);
    }
    if constraints.excluded_servers.contains(&server.name) {
        return Some(FilterStage::ExcludedServer);
    }
    None
}

/// Whether a catalog-exposed feature bit holds (T-4). Port forwarding
/// has no catalog bit and is evaluated against the entitlement seam in
/// [`required_features_stage`].
fn catalog_feature_holds(server: &LogicalServer, feature: FeatureConstraint) -> bool {
    match feature {
        FeatureConstraint::P2p => server.features.p2p(),
        FeatureConstraint::Tor => server.features.tor(),
        FeatureConstraint::SecureCore => server.features.secure_core(),
        FeatureConstraint::Streaming => server.features.streaming(),
        FeatureConstraint::Ipv6 => server.features.ipv6(),
        FeatureConstraint::PortForwarding => false,
    }
}

/// The required-features stage (T-4/FR-23H). Port forwarding evaluates
/// against the entitlement seam (`unwrap_or(false)` is fail-closed;
/// the up-front composition check makes `None` unreachable here).
fn required_features_stage(
    server: &LogicalServer,
    constraints: &Constraints,
    context: &SelectionContext,
) -> Option<FilterStage> {
    constraints
        .required_features
        .iter()
        .any(|feature| match feature {
            // FR-87: entitled AND this server is in the composed
            // capability set. The set is provably present here (the
            // entry checks refuse None under entitlement); an empty
            // composed set eliminates every server — the honest "no
            // server is capable" outcome.
            FeatureConstraint::PortForwarding => {
                !context.port_forwarding_entitled.unwrap_or(false)
                    || !context
                        .port_forwarding_capable
                        .as_ref()
                        .is_some_and(|capable| capable.contains(&server.id))
            }
            other => !catalog_feature_holds(server, *other),
        })
        .then_some(FilterStage::RequiredFeatures)
}

/// Whether an online physical exposes the required protocol (the
/// per-protocol presence map IS the support set per the S6 catalog
/// contract; a legacy `EntryIP`-only physical proves nothing).
fn protocol_holds(server: &LogicalServer, required: ProtocolConstraint) -> bool {
    server.servers.iter().filter(|p| p.is_online()).any(|p| {
        let Some(map) = p.entry_per_protocol.as_ref() else {
            return false;
        };
        match required {
            ProtocolConstraint::WireguardUdp => map.wireguard_udp.is_some(),
            ProtocolConstraint::WireguardTcp => map.wireguard_tcp.is_some(),
            ProtocolConstraint::Stealth => map.wireguard_tls.is_some(),
        }
    })
}

/// The protocol-compatibility stage (FR-23P's last core-owned filter).
fn protocol_stage(server: &LogicalServer, constraints: &Constraints) -> Option<FilterStage> {
    constraints
        .required_protocol
        .is_some_and(|required| !protocol_holds(server, required))
        .then_some(FilterStage::ProtocolCompatibility)
}

/// The first stage that eliminates this candidate, in FR-23P order.
fn eliminating_stage(
    server: &LogicalServer,
    request: &SelectionRequest,
    context: &SelectionContext,
) -> Option<FilterStage> {
    online_stage(server)
        .or_else(|| target_stage(server, &request.target))
        .or_else(|| physical_country_stage(server, &request.constraints))
        .or_else(|| exclusion_stage(server, &request.constraints))
        .or_else(|| required_features_stage(server, &request.constraints, context))
        .or_else(|| protocol_stage(server, &request.constraints))
}

/// Whether port forwarding appears in the required or optional set
/// (either slot needs the entitlement composition before it can be
/// evaluated — FR-23H).
fn needs_port_forwarding_composition(request: &SelectionRequest) -> bool {
    request
        .constraints
        .required_features
        .iter()
        .chain(request.constraints.optional_features.iter())
        .any(|f| *f == FeatureConstraint::PortForwarding)
}

/// Runs the hard-filter pipeline over the whole catalog: the survivors
/// plus FR-22's structured account of where every other candidate
/// went. Pure; no ranking (that is [`select`]'s policy stage).
///
/// Errors before any candidate work for malformed country inputs
/// ([`SelectionError::InvalidCountry`]), a country-excluding request
/// with no known physical country ([`SelectionError::PhysicalCountryRequired`],
/// FR-23Q), and a port-forwarding constraint without entitlement
/// composition ([`SelectionError::RequiresEntitlementComposition`],
/// FR-23H). An exact target reduced to nothing is
/// [`SelectionError::ExactServerUnavailable`] naming the refusing
/// stage — never a fallback (FR-23). A non-exact target reduced to
/// nothing returns an empty survivor set with the report; [`select`]
/// turns that into [`SelectionError::ConstraintsNotSatisfied`].
pub fn filter_candidates<'a>(
    catalog: &'a protonwire_store::catalog::CatalogDocument,
    request: &SelectionRequest,
    context: &SelectionContext,
) -> Result<(Vec<&'a LogicalServer>, EliminationReport), SelectionError> {
    validate_request_countries(request)?;
    // Codex PR#5 (P1): a Standard-fleet target plus the secure-core
    // feature constraint is unsatisfiable BY CONSTRUCTION — refuse at
    // validation with the typed contradiction instead of letting the
    // pipeline produce its baffling all-stages-empty report. (Exact
    // targets match identity before any fleet filtering, so an exact
    // SC server name remains the working spelling until PR-3's
    // routed target lands.)
    if !request.target.is_exact()
        && request
            .constraints
            .required_features
            .contains(&FeatureConstraint::SecureCore)
    {
        return Err(SelectionError::StandardFleetFeatureContradiction);
    }
    if request.constraints.exclude_physical_country
        && request.constraints.physical_country.is_none()
    {
        return Err(SelectionError::PhysicalCountryRequired);
    }
    if needs_port_forwarding_composition(request) && context.port_forwarding_entitled.is_none() {
        return Err(SelectionError::RequiresEntitlementComposition);
    }
    // Codex PR#5 round 4 (P1, FR-87): entitlement is account
    // permission, NOT server capability. An entitled request must
    // still carry the per-server capability set — the pre-fix arm
    // treated entitled as every-server-capable and could select a
    // server that cannot provide the feature.
    if needs_port_forwarding_composition(request)
        && context.port_forwarding_entitled == Some(true)
        && context.port_forwarding_capable.is_none()
    {
        return Err(SelectionError::PortForwardingCapabilityUnavailable);
    }

    let mut counts = [0usize; FilterStage::STAGES.len()];
    let mut survivors = Vec::new();
    for server in &catalog.logical_servers {
        match eliminating_stage(server, request, context) {
            Some(stage) => counts[stage.ordinal()] += 1,
            None => survivors.push(server),
        }
    }

    if request.target.is_exact() && survivors.is_empty() {
        // FR-23: never fall back. If the name matched nothing at all the
        // reason is absence; otherwise the eliminating stage of the
        // MATCHED server itself (M3 U1 review, P2: the pre-fix scan
        // took the first catalog-wide nonzero stage — an online-but-
        // eliminated exact target essentially always misreported
        // `offline` because some other server in any real catalog is
        // offline; the diagnosis must describe the matched server).
        let name = request.target.exact_name().unwrap_or_default().to_owned();
        let stage = match catalog
            .logical_servers
            .iter()
            .find(|server| request.target.matches_exact(server))
        {
            None => FilterStage::AbsentFromCatalog,
            // Under an exact target the matched server cannot be the
            // TARGET-GEOGRAPHY elimination (it matches the target), so
            // its own eliminating stage is the honest diagnosis; the
            // unwrap_or is defensive depth only.
            Some(matched_server) => eliminating_stage(matched_server, request, context)
                .unwrap_or(FilterStage::AbsentFromCatalog),
        };
        return Err(SelectionError::ExactServerUnavailable { name, stage });
    }

    let report = EliminationReport {
        considered: catalog.logical_servers.len(),
        survivors: survivors.len(),
        stages: FilterStage::STAGES
            .iter()
            .zip(counts)
            .map(|((stage, _), count)| (*stage, count))
            .collect(),
    };
    Ok((survivors, report))
}

/// Selects and ranks eligible servers from the cached catalog. Pure:
/// no I/O, no network, no clock, no RNG. See the module docs for the
/// stage order and the policy semantics.
pub fn select<'a>(
    catalog: &'a protonwire_store::catalog::CatalogDocument,
    request: &SelectionRequest,
    context: &SelectionContext,
) -> Result<SelectionOutcome<'a>, SelectionError> {
    let (candidates, mut report) = filter_candidates(catalog, request, context)?;
    let ranked = if request.target.is_exact()
        && candidates.len() == 1
        && matches!(request.policy, RankingPolicy::Official)
    {
        // Codex PR#5 (P2): an OFFICIAL exact target with ONE surviving
        // candidate needs no ranking decision — identity is the answer,
        // and a missing optional catalog Score must not make the
        // requested server unavailable (the FR-19A refusal governs
        // official ORDERING of a field, not a single match's
        // eligibility). Official-only by construction (round 2): every
        // other policy carries its own validation or data requirements
        // the normal path enforces — Balanced's weight validation and
        // latency-data checks, Random's entropy — and the shortcut
        // must not bypass them.
        candidates
            .into_iter()
            .map(|server| RankedCandidate {
                server,
                signals: ScoringSignals::catalog_only(server),
            })
            .collect()
    } else {
        match &request.policy {
            RankingPolicy::Official => rank_official(candidates)?,
            RankingPolicy::LowestLoad => rank_lowest_load(candidates, &mut report)?,
            RankingPolicy::Balanced { weights } => {
                rank_balanced(candidates, *weights, request, context, &mut report)?
            }
        }
    };
    if ranked.is_empty() {
        // A policy stage eliminated every survivor (FR-22 carries why).
        return Err(SelectionError::ConstraintsNotSatisfied { report });
    }
    Ok(SelectionOutcome { ranked, report })
}

/// The official policy: Proton's opaque catalog `Score` ascending
/// (FR-14/FR-19A). ANY eligible candidate lacking a score is the typed
/// missing-score refusal (T-1) — never a silent drop, never the
/// balanced model. Ties break by Proton-exposed load ascending, then
/// by logical id (the m3-plan's decision 2: deterministic output from
/// allowed signals only).
fn rank_official<'a>(
    candidates: Vec<&'a LogicalServer>,
) -> Result<Vec<RankedCandidate<'a>>, SelectionError> {
    let lacking = candidates
        .iter()
        .filter(|server| server.score.is_none())
        .count();
    if lacking > 0 {
        return Err(SelectionError::OfficialScoreUnavailable {
            lacking,
            eligible: candidates.len(),
        });
    }
    let mut ranked: Vec<RankedCandidate> = candidates
        .into_iter()
        .map(|server| RankedCandidate {
            server,
            signals: ScoringSignals::catalog_only(server),
        })
        .collect();
    ranked.sort_by(|a, b| {
        a.server
            .score
            .unwrap_or(f32::MAX)
            .total_cmp(&b.server.score.unwrap_or(f32::MAX))
            .then_with(|| {
                a.server
                    .load
                    .unwrap_or(i8::MAX)
                    .cmp(&b.server.load.unwrap_or(i8::MAX))
            })
            .then_with(|| a.server.id.cmp(&b.server.id))
    });
    Ok(ranked)
}

/// The `load` policy (FR-17): lowest Proton-exposed load; a candidate
/// without an exposed load is excluded WITH a report entry (decision 4
/// — never approximated).
fn rank_lowest_load<'a>(
    candidates: Vec<&'a LogicalServer>,
    report: &mut EliminationReport,
) -> Result<Vec<RankedCandidate<'a>>, SelectionError> {
    let mut ranked = Vec::with_capacity(candidates.len());
    let mut missing = 0usize;
    for server in candidates {
        match server.load {
            Some(_) => ranked.push(RankedCandidate {
                server,
                signals: ScoringSignals::catalog_only(server),
            }),
            None => missing += 1,
        }
    }
    report.charge(FilterStage::LoadNotExposed, missing);
    ranked.sort_by(|a, b| {
        a.server
            .load
            .unwrap_or(i8::MAX)
            .cmp(&b.server.load.unwrap_or(i8::MAX))
            .then_with(|| a.server.id.cmp(&b.server.id))
    });
    Ok(ranked)
}

/// The satisfied fraction of the optional feature set (FR-16's
/// feature-match signal; port forwarding evaluates against the
/// entitlement seam — fail-closed when unset).
fn optional_match_ratio(
    server: &LogicalServer,
    optional: &[FeatureConstraint],
    context: &SelectionContext,
) -> f32 {
    if optional.is_empty() {
        return 1.0;
    }
    let held = optional
        .iter()
        .filter(|feature| match feature {
            FeatureConstraint::PortForwarding => context.port_forwarding_entitled.unwrap_or(false),
            other => catalog_feature_holds(server, **other),
        })
        .count();
    held as f32 / optional.len() as f32
}

/// The ProtonWire `balanced` policy (FR-16, lower is better): the
/// weighted sum over load (Proton-exposed, normalized 0–1), latency
/// (caller-supplied, normalized against the observed set), feature
/// match, and — uniformly zero until their data sources exist post-M4 —
/// stability and history (the m3-plan's decision 5). A positive
/// latency weight with no observations at all refuses typed; a
/// candidate simply lacking an observation is excluded WITH a report
/// entry (the FR-18 shortlist boundary).
fn rank_balanced<'a>(
    candidates: Vec<&'a LogicalServer>,
    weights: WeightedSignals,
    request: &SelectionRequest,
    context: &SelectionContext,
    report: &mut EliminationReport,
) -> Result<Vec<RankedCandidate<'a>>, SelectionError> {
    if !weights.is_valid() {
        return Err(SelectionError::InvalidWeights(
            "hand-built weights must be finite and non-negative".to_owned(),
        ));
    }
    if weights.latency > 0.0 && context.latency.is_empty() {
        return Err(SelectionError::LatencyDataUnavailable {
            weight: weights.latency,
        });
    }

    let mut pool = Vec::with_capacity(candidates.len());
    let mut no_load = 0usize;
    let mut no_latency = 0usize;
    for server in candidates {
        if weights.load > 0.0 && server.load.is_none() {
            no_load += 1;
            continue;
        }
        if weights.latency > 0.0 && !context.latency.contains_key(&server.id) {
            no_latency += 1;
            continue;
        }
        pool.push(server);
    }
    report.charge(FilterStage::LoadNotExposed, no_load);
    report.charge(FilterStage::NoLatencyObservation, no_latency);

    let max_latency = pool
        .iter()
        .filter_map(|server| context.latency.get(&server.id))
        .map(Duration::as_secs_f32)
        .fold(0.0_f32, f32::max);

    let mut ranked: Vec<RankedCandidate> = pool
        .into_iter()
        .map(|server| {
            let load_term = if weights.load > 0.0 {
                weights.load * (server.load.unwrap_or(0) as f32 / 100.0)
            } else {
                0.0
            };
            let observed = context.latency.get(&server.id).copied();
            let latency_term = match (weights.latency > 0.0, observed) {
                (true, Some(latency)) if max_latency > 0.0 => {
                    weights.latency * (latency.as_secs_f32() / max_latency)
                }
                _ => 0.0,
            };
            let ratio =
                optional_match_ratio(server, &request.constraints.optional_features, context);
            let feature_match_term = weights.feature_match * (1.0 - ratio);
            let stability_term = 0.0;
            let history_term = 0.0;
            let total =
                load_term + latency_term + stability_term + feature_match_term + history_term;
            // Codex PR#5 round 3 (P2): multiple large-but-finite
            // weights pass `is_valid` yet their computed total can
            // overflow to infinity — overflowed candidates then
            // compare EQUAL (`inf == inf`) and fall through to the
            // logical-ID tiebreaker instead of the requested weighted
            // order. A non-finite computed term is a malformed weight
            // set for THIS candidate pool: refuse typed, never
            // mis-order.
            if !total.is_finite() {
                return Err(SelectionError::InvalidWeights(
                    "the weighted total overflows to a non-finite value for at least one \
                     candidate — the weight magnitudes cannot be ranked (the configuration \
                     surface expects weights summing to approximately 1.0)"
                        .to_owned(),
                ));
            }
            let signals = ScoringSignals {
                proton_score: server.score,
                load: server.load,
                latency: observed,
                weighted: Some(WeightedBreakdown {
                    load_term,
                    latency_term,
                    stability_term,
                    feature_match_term,
                    history_term,
                    total,
                }),
            };
            Ok(RankedCandidate { server, signals })
        })
        .collect::<Result<Vec<RankedCandidate>, SelectionError>>()?;
    ranked.sort_by(|a, b| {
        let (Some(a_total), Some(b_total)) = (a.signals.weighted, b.signals.weighted) else {
            unreachable!("balanced always carries the breakdown")
        };
        a_total
            .total
            .total_cmp(&b_total.total)
            .then_with(|| a.server.id.cmp(&b.server.id))
    });
    Ok(ranked)
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

    /// The intermediate state (M3 U1 review nit): `latency` is PR-3's
    /// mode (the bounded on-demand prober); until then it must parse as
    /// an ordinary INVALID mode — never silently accepted, never the
    /// unsupported-SIGNAL class.
    #[test]
    fn latency_mode_is_invalid_until_pr3_wires_the_prober() {
        let err = RankingPolicy::parse("latency").unwrap_err();
        assert_eq!(
            err,
            SelectionError::InvalidRankingMode("latency".to_owned())
        );
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

    // ------------------------------------------------------------------
    // Slice 2 — the hard-filter pipeline and the exact match (T-2/T-3/
    // T-4, FR-22). Everything drives filter_candidates over synthetic
    // catalogs that parse against the recorded S6 contract.
    // ------------------------------------------------------------------

    /// A synthetic logical-server spec: everything the pipeline reads,
    /// defaulted to an unremarkable online Standard server.
    struct Spec {
        name: &'static str,
        entry: &'static str,
        exit: &'static str,
        tier: i8,
        features: u64,
        status: Option<i8>,
        load: Option<i8>,
        score: Option<f32>,
        city: Option<&'static str>,
        state: Option<&'static str>,
        gateway: Option<&'static str>,
        online_physicals: usize,
        offline_physicals: usize,
        protocols: Vec<&'static str>,
        /// Append one extra OFFLINE physical carrying the full protocol
        /// map (the "the map exists but only on a dead physical" case).
        offline_physical_with_map: bool,
    }

    impl Spec {
        fn new(name: &'static str, exit: &'static str) -> Self {
            Self {
                name,
                entry: exit,
                exit,
                tier: 2,
                features: 0,
                status: Some(1),
                load: Some(20),
                score: Some(1.0),
                city: None,
                state: None,
                gateway: None,
                online_physicals: 1,
                offline_physicals: 0,
                protocols: vec!["wireguard_udp"],
                offline_physical_with_map: false,
            }
        }

        fn json(&self) -> String {
            let mut fields = format!(
                r#""ID":"id-{}","Name":"{}","EntryCountry":"{}","ExitCountry":"{}","Tier":{},"Features":{}"#,
                self.name, self.name, self.entry, self.exit, self.tier, self.features
            );
            if let Some(status) = self.status {
                fields.push_str(&format!(r#","Status":{status}"#));
            }
            if let Some(load) = self.load {
                fields.push_str(&format!(r#","Load":{load}"#));
            }
            if let Some(score) = self.score {
                fields.push_str(&format!(r#","Score":{score:?}"#));
            }
            if let Some(city) = self.city {
                fields.push_str(&format!(r#","City":"{city}""#));
            }
            if let Some(state) = self.state {
                fields.push_str(&format!(r#","State":"{state}""#));
            }
            if let Some(gateway) = self.gateway {
                fields.push_str(&format!(r#","GatewayName":"{gateway}""#));
            }
            let protocol_map = |protocols: &[&str]| {
                let map: Vec<String> = protocols
                    .iter()
                    .map(|protocol| {
                        let field = match *protocol {
                            "wireguard_udp" => "WireGuardUDP",
                            "wireguard_tcp" => "WireGuardTCP",
                            "stealth" => "WireGuardTLS",
                            _ => panic!("unknown test protocol {protocol}"),
                        };
                        format!(r#""{field}":{{"IPv4":"192.0.2.1","Ports":[443]}}"#)
                    })
                    .collect();
                if map.is_empty() {
                    String::new()
                } else {
                    format!(r#","EntryPerProtocol":{{{}}}"#, map.join(","))
                }
            };
            let mut physicals = Vec::new();
            let total = self.online_physicals
                + self.offline_physicals
                + usize::from(self.offline_physical_with_map);
            for index in 0..total {
                let online = index < self.online_physicals;
                // The protocol map rides the first ONLINE physical —
                // unless the offline-with-map knob is set, in which case
                // the map lives ONLY on the appended dead physical.
                let map = if (index == 0 && online && !self.offline_physical_with_map)
                    || (self.offline_physical_with_map && index == total - 1)
                {
                    protocol_map(&self.protocols)
                } else {
                    String::new()
                };
                let status = if online { 1 } else { 0 };
                physicals.push(format!(
                    r#"{{"Domain":"p{index}.example","Status":{status}{map}}}"#
                ));
            }
            format!(r#"{{{fields},"Servers":[{}]}}"#, physicals.join(","))
        }
    }

    fn build_catalog(specs: &[Spec]) -> protonwire_store::catalog::CatalogDocument {
        let servers: Vec<String> = specs.iter().map(|s| s.json()).collect();
        let body = format!(
            r#"{{"Code":1000,"StatusID":"t","LogicalServers":[{}]}}"#,
            servers.join(",")
        );
        protonwire_store::catalog::CatalogDocument::from_bytes(body.as_bytes())
            .unwrap_or_else(|e| panic!("test catalog must parse against the S6 contract: {e}"))
    }

    fn official(target: Target) -> SelectionRequest {
        SelectionRequest {
            target,
            policy: RankingPolicy::Official,
            constraints: Constraints::default(),
        }
    }

    fn stage_count(report: &EliminationReport, stage: FilterStage) -> usize {
        report
            .stages()
            .iter()
            .find(|(s, _)| *s == stage)
            .map(|(_, count)| *count)
            .expect("every stage appears in the report")
    }

    fn names<'a>(servers: &[&'a LogicalServer]) -> Vec<&'a str> {
        servers.iter().map(|s| s.name.as_str()).collect()
    }

    #[test]
    fn country_target_limits_to_that_country() {
        // FR-20: a provided country limits selection to it.
        let catalog = build_catalog(&[
            Spec::new("GB#1", "GB"),
            Spec::new("GB#2", "GB"),
            Spec::new("US#1", "US"),
        ]);
        let (survivors, report) = filter_candidates(
            &catalog,
            &official(Target::Country("GB".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(names(&survivors), ["GB#1", "GB#2"]);
        assert_eq!(stage_count(&report, FilterStage::TargetGeography), 1);
        assert_eq!(report.considered(), 3);
        assert_eq!(report.survivors(), 2);
    }

    #[test]
    fn excluded_countries_are_never_selected_and_apply_to_fastest() {
        // T-2/FR-21/FR-21A: exclusions are hard filters on the Fastest
        // pool too.
        let catalog = build_catalog(&[
            Spec::new("GB#1", "GB"),
            Spec::new("US#1", "US"),
            Spec::new("AU#1", "AU"),
        ]);
        let mut request = official(Target::Fastest);
        request.constraints.excluded_countries = vec!["US".into(), "AU".into()];
        let (survivors, report) =
            filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap();
        assert_eq!(names(&survivors), ["GB#1"]);
        assert_eq!(stage_count(&report, FilterStage::ExcludedCountry), 2);
    }

    #[test]
    fn the_fr23p_stage_order_charges_the_earliest_stage() {
        // FR-23P's order is observable: a server that is BOTH offline
        // and excluded counts as offline (online state precedes the
        // exclusions); a country-target miss that is also excluded
        // counts as a geography miss (geography precedes exclusions).
        let catalog = build_catalog(&[
            Spec::new("GB#1", "GB"), // right country, excluded -> ExcludedCountry
            Spec {
                status: Some(0),
                ..Spec::new("US#1", "US")
            }, // offline AND excluded -> Offline (online precedes exclusions)
            Spec::new("DE#1", "DE"), // wrong country AND excluded -> TargetGeography
            Spec::new("GB#2", "GB"), // right country, excluded -> ExcludedCountry
        ]);
        let mut request = official(Target::Country("GB".into()));
        request.constraints.excluded_countries = vec!["US".into(), "DE".into(), "GB".into()];
        let (survivors, report) =
            filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap();
        assert!(survivors.is_empty());
        assert_eq!(stage_count(&report, FilterStage::Offline), 1);
        assert_eq!(stage_count(&report, FilterStage::TargetGeography), 1);
        assert_eq!(stage_count(&report, FilterStage::ExcludedCountry), 2);
    }

    #[test]
    fn excluded_states_cities_and_servers_are_enforced() {
        // FR-21A: state/city/exact-server exclusions sit at the same
        // hard-filter stage as countries.
        let catalog = build_catalog(&[
            Spec {
                state: Some("California"),
                ..Spec::new("US-CA#1", "US")
            },
            Spec {
                city: Some("London"),
                ..Spec::new("GB#1", "GB")
            },
            Spec {
                city: Some("Manchester"),
                ..Spec::new("GB#2", "GB")
            },
        ]);
        let mut request = official(Target::Fastest);
        request.constraints.excluded_states = vec!["California".into()];
        request.constraints.excluded_cities = vec!["London".into()];
        request.constraints.excluded_servers = vec!["GB#2".into()];
        let (survivors, report) =
            filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap();
        assert!(survivors.is_empty(), "every candidate is excluded");
        assert_eq!(stage_count(&report, FilterStage::ExcludedState), 1);
        assert_eq!(stage_count(&report, FilterStage::ExcludedCity), 1);
        assert_eq!(stage_count(&report, FilterStage::ExcludedServer), 1);
    }

    #[test]
    fn state_and_city_targets_match_case_insensitively() {
        // User-typed prose against catalog casing: ASCII-folded
        // equality, disclosed canonicalization (not approximation —
        // no substring or prefix matching anywhere).
        let catalog = build_catalog(&[
            Spec {
                state: Some("California"),
                ..Spec::new("US-CA#1", "US")
            },
            Spec {
                city: Some("London"),
                ..Spec::new("GB#1", "GB")
            },
            Spec {
                city: Some("Londonderry"),
                ..Spec::new("GB#2", "GB")
            },
        ]);
        let (survivors, _) = filter_candidates(
            &catalog,
            &official(Target::State("california".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(names(&survivors), ["US-CA#1"]);

        let (survivors, _) = filter_candidates(
            &catalog,
            &official(Target::City("london".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(
            names(&survivors),
            ["GB#1"],
            "prefix/suffix names must not match: only exact folded equality"
        );
    }

    #[test]
    fn physical_country_exclusion_removes_only_that_country() {
        // FR-23Q semantics as the core enforces them once GIVEN the
        // country (the resolution precedence is PR-2's): exits in the
        // physical country are eliminated at its dedicated stage.
        let catalog = build_catalog(&[
            Spec::new("GB#1", "GB"),
            Spec::new("CH#1", "CH"),
            Spec::new("GB#2", "GB"),
        ]);
        let mut request = official(Target::Fastest);
        request.constraints.exclude_physical_country = true;
        request.constraints.physical_country = Some("GB".into());
        let (survivors, report) =
            filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap();
        assert_eq!(names(&survivors), ["CH#1"]);
        assert_eq!(
            stage_count(&report, FilterStage::PhysicalCountryExclusion),
            2
        );
    }

    #[test]
    fn country_exclusion_without_a_physical_country_refuses() {
        // FR-23Q: it must not connect without the exclusion.
        let catalog = build_catalog(&[Spec::new("GB#1", "GB")]);
        let mut request = official(Target::Fastest);
        request.constraints.exclude_physical_country = true;
        let err = filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap_err();
        assert_eq!(err, SelectionError::PhysicalCountryRequired);
    }

    #[test]
    fn non_canonical_country_inputs_are_refused() {
        // Uppercase alpha-2 only; canonicalization belongs to the
        // calling surface, not the pure core.
        let catalog = build_catalog(&[Spec::new("GB#1", "GB")]);
        for bad in ["gb", "USA", "G", "G1"] {
            let err = filter_candidates(
                &catalog,
                &official(Target::Country(bad.into())),
                &SelectionContext::default(),
            )
            .unwrap_err();
            assert_eq!(err, SelectionError::InvalidCountry(bad.to_owned()));
        }
        let mut request = official(Target::Fastest);
        request.constraints.excluded_countries = vec!["usa".into()];
        let err = filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap_err();
        assert_eq!(err, SelectionError::InvalidCountry("usa".into()));
    }

    #[test]
    fn unknown_status_is_excluded_fail_closed() {
        // FR-13B: an absent status is UNKNOWN — never fabricated to
        // online, never connectable.
        let catalog = build_catalog(&[
            Spec {
                status: None,
                ..Spec::new("GB#1", "GB")
            },
            Spec::new("GB#2", "GB"),
        ]);
        let (survivors, report) = filter_candidates(
            &catalog,
            &official(Target::Country("GB".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(names(&survivors), ["GB#2"]);
        assert_eq!(stage_count(&report, FilterStage::UnknownStatus), 1);
    }

    #[test]
    fn offline_logicals_and_dead_physical_sets_are_excluded() {
        let catalog = build_catalog(&[
            Spec {
                status: Some(0),
                ..Spec::new("GB#1", "GB")
            },
            Spec {
                online_physicals: 0,
                offline_physicals: 2,
                ..Spec::new("GB#2", "GB")
            },
            Spec::new("GB#3", "GB"),
        ]);
        let (survivors, report) = filter_candidates(
            &catalog,
            &official(Target::Country("GB".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(names(&survivors), ["GB#3"]);
        assert_eq!(stage_count(&report, FilterStage::Offline), 1);
        assert_eq!(stage_count(&report, FilterStage::AllPhysicalsOffline), 1);
    }

    #[test]
    fn fastest_targets_the_standard_fleet_only() {
        // FR-23L: gateway and Secure Core logicals are other connection
        // types; Fastest means the Standard target. Tor/P2P bits are
        // Standard-fleet capabilities.
        let catalog = build_catalog(&[
            Spec::new("GB#1", "GB"),
            Spec {
                gateway: Some("acme-corp"),
                ..Spec::new("acme-corp#1", "SE")
            },
            Spec {
                entry: "CH",
                features: 1, // Secure Core bit
                ..Spec::new("CH-SE#1", "SE")
            },
            Spec {
                features: 4 | 2, // P2P | Tor
                ..Spec::new("NL#1", "NL")
            },
        ]);
        let (survivors, report) = filter_candidates(
            &catalog,
            &official(Target::Fastest),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(names(&survivors), ["GB#1", "NL#1"]);
        assert_eq!(stage_count(&report, FilterStage::ServerType), 2);
    }

    #[test]
    fn required_features_filter_on_the_catalog_bits() {
        // T-4: p2p/tor/secure-core/streaming/ipv6 constraints.
        let catalog = build_catalog(&[
            Spec {
                features: 4, // P2P
                ..Spec::new("GB#1", "GB")
            },
            Spec {
                features: 2, // Tor
                ..Spec::new("GB#2", "GB")
            },
            Spec::new("GB#3", "GB"),
        ]);
        let mut request = official(Target::Fastest);
        request.constraints.required_features = vec![FeatureConstraint::P2p];
        let (survivors, report) =
            filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap();
        assert_eq!(names(&survivors), ["GB#1"]);
        assert_eq!(stage_count(&report, FilterStage::RequiredFeatures), 2);

        // The whole catalog-bit family holds.
        let mut request = official(Target::Fastest);
        request.constraints.required_features = vec![FeatureConstraint::Tor];
        let (survivors, _) =
            filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap();
        assert_eq!(names(&survivors), ["GB#2"]);

        let mut streaming = Spec::new("US#1", "US");
        streaming.features = 8; // Streaming
        let mut ipv6 = Spec::new("US#2", "US");
        ipv6.features = 16; // IPv6
        let catalog = build_catalog(&[streaming, ipv6]);
        let mut request = official(Target::Fastest);
        request.constraints.required_features =
            vec![FeatureConstraint::Streaming, FeatureConstraint::Ipv6];
        let (survivors, report) =
            filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap();
        assert!(survivors.is_empty(), "no single server carries both bits");
        assert_eq!(stage_count(&report, FilterStage::RequiredFeatures), 2);
    }

    #[test]
    fn port_forwarding_requires_entitlement_composition() {
        // FR-23H: no catalog field exists upstream; the constraint
        // refuses typed until the daemon composes S8 entitlement — in
        // the required AND the optional slot (the optional one feeds
        // scoring, so it cannot be silently ignored either).
        let catalog = build_catalog(&[Spec::new("GB#1", "GB")]);
        let mut required = official(Target::Fastest);
        required.constraints.required_features = vec![FeatureConstraint::PortForwarding];
        let err = filter_candidates(&catalog, &required, &SelectionContext::default()).unwrap_err();
        assert_eq!(err, SelectionError::RequiresEntitlementComposition);

        let mut optional = official(Target::Fastest);
        optional.constraints.optional_features = vec![FeatureConstraint::PortForwarding];
        let err = filter_candidates(&catalog, &optional, &SelectionContext::default()).unwrap_err();
        assert_eq!(err, SelectionError::RequiresEntitlementComposition);

        // Composed false: every candidate fails the feature stage; the
        // report says so (FR-22, not a bare refusal).
        let context = SelectionContext {
            port_forwarding_entitled: Some(false),
            ..SelectionContext::default()
        };
        let (survivors, report) = filter_candidates(&catalog, &required, &context).unwrap();
        assert!(survivors.is_empty());
        assert_eq!(stage_count(&report, FilterStage::RequiredFeatures), 1);

        // Composed true WITHOUT the capability set: the typed refusal
        // (Codex PR#5 round 4 — the pre-fix shape passed here for
        // every server, selecting PF-incapable servers under an
        // entitled account).
        let context = SelectionContext {
            port_forwarding_entitled: Some(true),
            ..SelectionContext::default()
        };
        let err = filter_candidates(&catalog, &required, &context).unwrap_err();
        assert_eq!(
            err,
            SelectionError::PortForwardingCapabilityUnavailable,
            "entitlement alone must never satisfy FR-87"
        );

        // Entitled + the composed capability set naming GB#1 only:
        // GB#2 eliminates at the feature stage; GB#1 survives.
        let capable: std::collections::BTreeSet<String> =
            ["id-GB#1".to_owned()].into_iter().collect();
        let context = SelectionContext {
            port_forwarding_entitled: Some(true),
            port_forwarding_capable: Some(capable),
            ..SelectionContext::default()
        };
        let two = build_catalog(&[Spec::new("GB#1", "GB"), Spec::new("GB#2", "GB")]);
        let (survivors, report) = filter_candidates(&two, &required, &context).unwrap();
        assert_eq!(names(&survivors), ["GB#1"]);
        assert_eq!(stage_count(&report, FilterStage::RequiredFeatures), 1);

        // Entitled + an EMPTY composed set: the honest "no server is
        // capable" outcome — every candidate eliminates with the
        // report, not a bare refusal.
        let context = SelectionContext {
            port_forwarding_entitled: Some(true),
            port_forwarding_capable: Some(std::collections::BTreeSet::new()),
            ..SelectionContext::default()
        };
        let (survivors, report) = filter_candidates(&two, &required, &context).unwrap();
        assert!(survivors.is_empty());
        assert_eq!(stage_count(&report, FilterStage::RequiredFeatures), 2);
    }

    #[test]
    fn protocol_compatibility_uses_online_physical_presence() {
        // The per-protocol map IS the support set (S6): a physical with
        // no map (the legacy EntryIP-only shape) proves nothing, and a
        // map that exists only on an OFFLINE physical does not save the
        // candidate.
        let mut legacy = Spec::new("GB#1", "GB");
        legacy.protocols = Vec::new(); // no per-protocol map at all
        let mut stealth = Spec::new("GB#2", "GB");
        stealth.protocols = vec!["stealth"];
        let mut both = Spec::new("GB#3", "GB");
        both.protocols = vec!["wireguard_udp", "wireguard_tcp", "stealth"];
        let mut dead_map = Spec::new("GB#4", "GB");
        dead_map.protocols = vec!["wireguard_tcp"];
        dead_map.offline_physical_with_map = true; // the only map is on a dead physical
        let catalog = build_catalog(&[legacy, stealth, both, dead_map]);

        let mut request = official(Target::Fastest);
        request.constraints.required_protocol = Some(ProtocolConstraint::WireguardTcp);
        let (survivors, report) =
            filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap();
        assert_eq!(names(&survivors), ["GB#3"]);
        assert_eq!(stage_count(&report, FilterStage::ProtocolCompatibility), 3);

        let mut request = official(Target::Fastest);
        request.constraints.required_protocol = Some(ProtocolConstraint::Stealth);
        let (survivors, _) =
            filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap();
        assert_eq!(
            names(&survivors),
            ["GB#2", "GB#3"],
            "Stealth maps to the catalog's WireGuardTLS presence"
        );
    }

    #[test]
    fn exact_server_selects_that_server() {
        // T-3/FR-23: the exact name — and only it.
        let catalog = build_catalog(&[
            Spec::new("UK#42", "GB"),
            Spec::new("UK#43", "GB"),
            Spec::new("GB#1", "GB"),
        ]);
        let (survivors, report) = filter_candidates(
            &catalog,
            &official(Target::Server("UK#42".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(names(&survivors), ["UK#42"]);
        assert_eq!(stage_count(&report, FilterStage::TargetGeography), 2);
    }

    /// Codex PR#5 (P2): an exact target with ONE surviving candidate
    /// needs no ranking decision — a missing optional catalog Score
    /// must not make the requested server unavailable. The
    /// missing-score refusal (FR-19A) governs official ORDERING of a
    /// field, not the identity of a single match.
    #[test]
    fn an_exact_server_without_a_score_still_selects() {
        let mut unscored = Spec::new("UK#42", "GB");
        unscored.score = None;
        let catalog = build_catalog(&[unscored, Spec::new("GB#1", "GB")]);
        let outcome = select(
            &catalog,
            &official(Target::Server("UK#42".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(outcome.ranked.len(), 1);
        assert_eq!(outcome.ranked[0].server.name, "UK#42");
    }

    /// Codex PR#5 round 2 (P2): the exact-single-candidate exemption is
    /// OFFICIAL-only — a Balanced exact request still validates its
    /// weights and data requirements through the normal path. Pre-fix,
    /// a single-candidate exact target with hand-built NaN weights
    /// sailed through the shortcut, violating the documented
    /// validation guarantee.
    #[test]
    fn the_exact_single_candidate_exemption_does_not_bypass_balanced_validation() {
        let catalog = build_catalog(&[Spec::new("UK#42", "GB"), Spec::new("GB#1", "GB")]);
        let nan = f32::NAN;
        let mut request = official(Target::Server("UK#42".into()));
        request.policy = RankingPolicy::Balanced {
            weights: WeightedSignals {
                load: nan,
                ..WeightedSignals::DEFAULT
            },
        };
        let err = select(&catalog, &request, &SelectionContext::default()).unwrap_err();
        assert!(
            matches!(err, SelectionError::InvalidWeights { .. }),
            "the shortcut must not bypass weight validation: {err}"
        );
    }

    /// Codex PR#5 round 3 (P2): large-but-finite weights pass
    /// `is_valid` yet their computed total can overflow to infinity —
    /// overflowed candidates then compare EQUAL and fall to the
    /// logical-ID tiebreaker instead of the requested weighted order.
    /// A non-finite computed total refuses typed.
    #[test]
    fn balanced_totals_that_overflow_refuse_rather_than_mis_order() {
        // load 100/100 and a zero optional-match ratio saturate BOTH
        // terms: f32::MAX + f32::MAX = +inf — the shape the old check
        // let through to the id tiebreaker.
        let mut uk1 = Spec::new("UK#1", "GB");
        uk1.load = Some(100);
        let mut gb2 = Spec::new("GB#2", "GB");
        gb2.load = Some(100);
        let catalog = build_catalog(&[uk1, gb2]);
        let mut request = official(Target::Country("GB".into()));
        // The servers lack Tor: the optional-match ratio is 0, so the
        // feature term saturates too — MAX + MAX = inf.
        request.constraints.optional_features = vec![FeatureConstraint::Tor];
        request.policy = RankingPolicy::Balanced {
            weights: WeightedSignals {
                load: f32::MAX,
                feature_match: f32::MAX,
                ..WeightedSignals::DEFAULT_ZEROED
            },
        };
        let err = select(&catalog, &request, &SelectionContext::default()).unwrap_err();
        assert!(
            matches!(err, SelectionError::InvalidWeights { .. }),
            "an overflowing weight set must refuse, never mis-order: {err}"
        );
        assert!(
            err.to_string().contains("non-finite"),
            "the refusal names the overflow: {err}"
        );
    }

    /// Codex PR#5 (P1): a Standard-fleet target plus the
    /// `secure-core` FEATURE constraint is unsatisfiable BY
    /// CONSTRUCTION (the type stage removes every SC logical; the
    /// feature stage then removes every Standard one). The
    /// contradiction is detectable at validation time and refuses with
    /// a typed error naming it and the routed target that lands in
    /// PR-3 — never the pipeline's baffling all-stages-empty report.
    #[test]
    fn a_standard_fleet_target_with_the_secure_core_feature_refuses_at_validation() {
        let catalog = build_catalog(&[Spec::new("UK#1", "GB"), Spec::new("GB#1", "GB")]);
        let mut request = official(Target::Fastest);
        request.constraints.required_features = vec![FeatureConstraint::SecureCore];
        let err = select(&catalog, &request, &SelectionContext::default()).unwrap_err();
        assert!(
            matches!(err, SelectionError::StandardFleetFeatureContradiction),
            "the typed contradiction, got: {err}"
        );
        let message = err.to_string();
        assert!(
            message.contains("secure-core"),
            "names the feature: {message}"
        );
        assert!(
            message.contains("routed"),
            "points at the routed Secure Core target: {message}"
        );
    }

    #[test]
    fn exact_server_absent_never_falls_back() {
        // FR-23: no silent substitution of another server.
        let catalog = build_catalog(&[Spec::new("UK#42", "GB"), Spec::new("GB#1", "GB")]);
        let err = filter_candidates(
            &catalog,
            &official(Target::Server("UK#99".into())),
            &SelectionContext::default(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            SelectionError::ExactServerUnavailable {
                name: "UK#99".into(),
                stage: FilterStage::AbsentFromCatalog,
            }
        );
        let message = err.to_string();
        assert!(
            message.contains("UK#99") && message.contains("FR-23"),
            "{message}"
        );
    }

    #[test]
    fn exact_server_offline_never_falls_back() {
        // The name matches but the server is unusable: name the stage.
        let catalog = build_catalog(&[
            Spec {
                status: Some(0),
                ..Spec::new("UK#42", "GB")
            },
            Spec::new("GB#1", "GB"),
        ]);
        let err = filter_candidates(
            &catalog,
            &official(Target::Server("UK#42".into())),
            &SelectionContext::default(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            SelectionError::ExactServerUnavailable {
                name: "UK#42".into(),
                stage: FilterStage::Offline,
            }
        );
    }

    /// M3 U1 review, P2: the exact-refusal's stage diagnosis must be
    /// the MATCHED server's own eliminating stage — never the first
    /// catalog-wide nonzero stage. Pre-fix, an ONLINE exact target
    /// eliminated by the user's server exclusion misreported `offline`
    /// whenever any unrelated server in the catalog was offline (which
    /// real catalogs always have).
    #[test]
    fn exact_server_elimination_names_the_matched_servers_own_stage() {
        let catalog = build_catalog(&[
            // The exact target: online, but user-excluded.
            Spec::new("UK#42", "GB"),
            // An unrelated OFFLINE server whose stage would have won
            // the pre-fix catalog-wide ordinal race.
            Spec {
                status: Some(0),
                ..Spec::new("GB#1", "GB")
            },
        ]);
        let mut request = official(Target::Server("UK#42".into()));
        request.constraints.excluded_servers = vec!["UK#42".into()];
        let err = filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap_err();
        assert_eq!(
            err,
            SelectionError::ExactServerUnavailable {
                name: "UK#42".into(),
                stage: FilterStage::ExcludedServer,
            },
            "the diagnosis describes the matched server (user-excluded), not GB#1's offline"
        );
    }

    #[test]
    fn exact_matching_covers_special_name_forms() {
        // Secure Core `CH-SE#1` and gateway `acme-corp#1` are logical
        // names: exact matching serves them without the Standard-type
        // filter (the routed-Secure-Core TARGET is this milestone's
        // PR-3; the NAME resolves today).
        let mut secure_core = Spec::new("CH-SE#1", "SE");
        secure_core.entry = "CH";
        secure_core.features = 1;
        let mut gateway = Spec::new("acme-corp#1", "SE");
        gateway.gateway = Some("acme-corp");
        let catalog = build_catalog(&[secure_core, gateway, Spec::new("GB#1", "GB")]);

        let (survivors, _) = filter_candidates(
            &catalog,
            &official(Target::Server("CH-SE#1".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(names(&survivors), ["CH-SE#1"]);

        let (survivors, _) = filter_candidates(
            &catalog,
            &official(Target::Server("acme-corp#1".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(names(&survivors), ["acme-corp#1"]);

        // The gateway TARGET form matches the fleet identity.
        let (survivors, _) = filter_candidates(
            &catalog,
            &official(Target::Gateway("acme-corp".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(names(&survivors), ["acme-corp#1"]);

        let err = filter_candidates(
            &catalog,
            &official(Target::Gateway("other-corp".into())),
            &SelectionContext::default(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            SelectionError::ExactServerUnavailable {
                name: "other-corp".into(),
                stage: FilterStage::AbsentFromCatalog,
            }
        );
    }

    #[test]
    fn the_report_accounts_for_every_candidate() {
        // FR-22: considered == survivors + the sum of every stage count.
        let catalog = build_catalog(&[
            Spec {
                features: 4, // P2P — the survivor
                ..Spec::new("GB#1", "GB")
            },
            Spec {
                status: Some(0),
                ..Spec::new("US#1", "US")
            },
            Spec {
                gateway: Some("acme-corp"),
                ..Spec::new("acme-corp#1", "SE")
            },
            Spec {
                features: 4,
                ..Spec::new("DE#1", "DE")
            },
        ]);
        let mut request = official(Target::Fastest);
        request.constraints.excluded_countries = vec!["DE".into()];
        request.constraints.required_features = vec![FeatureConstraint::P2p];
        let (survivors, report) =
            filter_candidates(&catalog, &request, &SelectionContext::default()).unwrap();
        assert_eq!(names(&survivors), ["GB#1"]);
        let eliminated: usize = report.stages().iter().map(|(_, count)| count).sum();
        assert_eq!(
            report.considered(),
            report.survivors() + eliminated,
            "every candidate is accounted for exactly once"
        );
        assert_eq!(stage_count(&report, FilterStage::Offline), 1);
        assert_eq!(stage_count(&report, FilterStage::ServerType), 1);
        assert_eq!(stage_count(&report, FilterStage::ExcludedCountry), 1);
        let rendered = report.to_string();
        assert!(
            rendered.contains("4 considered, 1 survivors") && rendered.contains("1 offline"),
            "the Display carries the accounting: {rendered}"
        );
    }

    // ------------------------------------------------------------------
    // Slice 3 — the ranking policies through select (T-1): official
    // ordering and its refusal class, lowest load, the balanced
    // weighted model, and the FR-22 end-to-end error.
    // ------------------------------------------------------------------

    fn spec_with(
        name: &'static str,
        exit: &'static str,
        score: Option<f32>,
        load: Option<i8>,
    ) -> Spec {
        Spec {
            score,
            load,
            ..Spec::new(name, exit)
        }
    }

    #[test]
    fn official_orders_by_proton_score_ascending() {
        // FR-14/FR-19A: official = Proton's opaque catalog Score
        // ascending after hard filters; no local signal participates.
        let catalog = build_catalog(&[
            spec_with("GB#1", "GB", Some(1.5), Some(50)),
            spec_with("GB#2", "GB", Some(0.5), Some(90)),
            spec_with("GB#3", "GB", Some(2.5), Some(10)),
        ]);
        let outcome = select(
            &catalog,
            &official(Target::Country("GB".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        let ranked: Vec<&str> = outcome
            .ranked
            .iter()
            .map(|c| c.server.name.as_str())
            .collect();
        assert_eq!(ranked, ["GB#2", "GB#1", "GB#3"]);
        assert_eq!(outcome.ranked[0].signals.proton_score, Some(0.5));
        assert_eq!(outcome.ranked[0].signals.weighted, None);
        assert_eq!(outcome.report.survivors(), 3);
    }

    #[test]
    fn official_ties_break_by_load_then_id() {
        // The plan's decision 2: Score ascending, ties by Proton-exposed
        // Load ascending (an allowed Proton-exposed signal, FR-19), then
        // by logical id — deterministic output, never locally invented.
        let catalog = build_catalog(&[
            spec_with("GB#B", "GB", Some(1.0), Some(40)),
            spec_with("GB#A", "GB", Some(1.0), Some(40)),
            spec_with("GB#C", "GB", Some(1.0), Some(10)),
        ]);
        let outcome = select(
            &catalog,
            &official(Target::Country("GB".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        let ranked: Vec<&str> = outcome
            .ranked
            .iter()
            .map(|c| c.server.name.as_str())
            .collect();
        assert_eq!(ranked, ["GB#C", "GB#A", "GB#B"]);
    }

    #[test]
    fn official_missing_score_refuses_never_substitutes_balanced() {
        // T-1/FR-19A: ANY eligible candidate lacking a Score is a typed
        // refusal suggesting an eligible catalog refresh — never a
        // silent drop, never the balanced model in disguise.
        let catalog = build_catalog(&[
            spec_with("GB#1", "GB", Some(1.0), Some(50)),
            spec_with("GB#2", "GB", None, Some(50)),
        ]);
        let err = select(
            &catalog,
            &official(Target::Country("GB".into())),
            &SelectionContext::default(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            SelectionError::OfficialScoreUnavailable {
                lacking: 1,
                eligible: 2,
            }
        );
        let message = err.to_string();
        assert!(
            message.contains("official-score-unavailable") && message.contains("refresh"),
            "the refusal carries its PRD token and the remediation: {message}"
        );
    }

    #[test]
    fn lowest_load_orders_by_exposed_load_and_reports_missing() {
        // FR-17 + decision 4: lowest Proton-exposed load; a missing load
        // is excluded WITH a report entry, never approximated.
        let catalog = build_catalog(&[
            spec_with("GB#1", "GB", Some(1.0), Some(80)),
            spec_with("GB#2", "GB", Some(2.0), Some(10)),
            spec_with("GB#3", "GB", Some(0.5), None),
        ]);
        let mut request = official(Target::Country("GB".into()));
        request.policy = RankingPolicy::LowestLoad;
        let outcome = select(&catalog, &request, &SelectionContext::default()).unwrap();
        let ranked: Vec<&str> = outcome
            .ranked
            .iter()
            .map(|c| c.server.name.as_str())
            .collect();
        assert_eq!(ranked, ["GB#2", "GB#1"]);
        assert_eq!(stage_count(&outcome.report, FilterStage::LoadNotExposed), 1);
        assert_eq!(outcome.report.survivors(), 2);

        // ALL loads missing: the policy eliminated everyone — FR-22
        // carries the reason.
        let catalog = build_catalog(&[
            spec_with("GB#1", "GB", Some(1.0), None),
            spec_with("GB#2", "GB", Some(2.0), None),
        ]);
        let err = select(&catalog, &request, &SelectionContext::default()).unwrap_err();
        match err {
            SelectionError::ConstraintsNotSatisfied { report } => {
                assert_eq!(stage_count(&report, FilterStage::LoadNotExposed), 2);
            }
            other => panic!("expected the FR-22 error, got {other}"),
        }
    }

    fn latency_context(pairs: &[(&str, u64)]) -> SelectionContext {
        SelectionContext {
            latency: pairs
                .iter()
                .map(|(id, ms)| ((*id).to_owned(), Duration::from_millis(*ms)))
                .collect(),
            port_forwarding_entitled: None,
            port_forwarding_capable: None,
        }
    }

    fn balanced(weights: WeightedSignals, target: Target) -> SelectionRequest {
        SelectionRequest {
            target,
            policy: RankingPolicy::Balanced { weights },
            constraints: Constraints::default(),
        }
    }

    #[test]
    fn balanced_orders_by_the_hand_computed_weighted_sum() {
        // FR-16, hand-checked: loads A=80 B=20 C=50; latencies
        // A=100ms B=200ms C=50ms; weights load=.5 latency=.5.
        // normalized latency (max 200ms): A=.5 B=1.0 C=.25.
        // totals: A=.5*.8+.5*.5=.65 B=.5*.2+.5*1=.6 C=.5*.5+.5*.25=.375.
        let catalog = build_catalog(&[
            spec_with("GB#A", "GB", Some(1.0), Some(80)),
            spec_with("GB#B", "GB", Some(1.0), Some(20)),
            spec_with("GB#C", "GB", Some(1.0), Some(50)),
        ]);
        let weights = WeightedSignals {
            load: 0.5,
            latency: 0.5,
            ..WeightedSignals::DEFAULT_ZEROED
        };
        let outcome = select(
            &catalog,
            &balanced(weights, Target::Country("GB".into())),
            &latency_context(&[("id-GB#A", 100), ("id-GB#B", 200), ("id-GB#C", 50)]),
        )
        .unwrap();
        let ranked: Vec<&str> = outcome
            .ranked
            .iter()
            .map(|c| c.server.name.as_str())
            .collect();
        assert_eq!(ranked, ["GB#C", "GB#B", "GB#A"]);
        let winner = &outcome.ranked[0];
        let breakdown = winner
            .signals
            .weighted
            .expect("balanced carries the breakdown");
        assert!((breakdown.load_term - 0.25).abs() < 1e-6);
        assert!((breakdown.latency_term - 0.125).abs() < 1e-6);
        assert!((breakdown.total - 0.375).abs() < 1e-6);
        assert_eq!(winner.signals.latency, Some(Duration::from_millis(50)));
    }

    #[test]
    fn balanced_latency_weight_without_observations_refuses() {
        // Decision 5: latency probing is PR-3; no table and a positive
        // latency weight is a typed refusal — no fabricated latencies.
        let catalog = build_catalog(&[spec_with("GB#1", "GB", Some(1.0), Some(50))]);
        let weights = WeightedSignals {
            latency: 0.4,
            ..WeightedSignals::DEFAULT_ZEROED
        };
        let err = select(
            &catalog,
            &balanced(weights, Target::Country("GB".into())),
            &SelectionContext::default(),
        )
        .unwrap_err();
        assert_eq!(err, SelectionError::LatencyDataUnavailable { weight: 0.4 });
    }

    #[test]
    fn balanced_ranks_the_observed_shortlist_and_reports_the_boundary() {
        // FR-18's shortlist boundary: candidates without an observation
        // are excluded WITH a report entry (never probed, never
        // guessed), not a global refusal.
        let catalog = build_catalog(&[
            spec_with("GB#1", "GB", Some(1.0), Some(50)),
            spec_with("GB#2", "GB", Some(1.0), Some(50)),
            spec_with("GB#3", "GB", Some(1.0), Some(50)),
        ]);
        let weights = WeightedSignals {
            latency: 1.0,
            ..WeightedSignals::DEFAULT_ZEROED
        };
        let outcome = select(
            &catalog,
            &balanced(weights, Target::Country("GB".into())),
            &latency_context(&[("id-GB#1", 80), ("id-GB#3", 20)]),
        )
        .unwrap();
        let ranked: Vec<&str> = outcome
            .ranked
            .iter()
            .map(|c| c.server.name.as_str())
            .collect();
        assert_eq!(ranked, ["GB#3", "GB#1"]);
        assert_eq!(
            stage_count(&outcome.report, FilterStage::NoLatencyObservation),
            1
        );
    }

    #[test]
    fn balanced_missing_load_is_excluded_with_a_report_entry() {
        let catalog = build_catalog(&[
            spec_with("GB#1", "GB", Some(1.0), Some(50)),
            spec_with("GB#2", "GB", Some(1.0), None),
        ]);
        let weights = WeightedSignals {
            load: 1.0,
            ..WeightedSignals::DEFAULT_ZEROED
        };
        let outcome = select(
            &catalog,
            &balanced(weights, Target::Country("GB".into())),
            &SelectionContext::default(),
        )
        .unwrap();
        let ranked: Vec<&str> = outcome
            .ranked
            .iter()
            .map(|c| c.server.name.as_str())
            .collect();
        assert_eq!(ranked, ["GB#1"]);
        assert_eq!(stage_count(&outcome.report, FilterStage::LoadNotExposed), 1);
    }

    #[test]
    fn balanced_stability_and_history_are_uniformly_zero_and_disclosed() {
        // Decision 5: no data source exists until post-M4 connection
        // statistics — the terms contribute uniformly zero (order-
        // neutral) and the report says nothing was fabricated.
        let catalog = build_catalog(&[
            spec_with("GB#1", "GB", Some(1.0), Some(50)),
            spec_with("GB#2", "GB", Some(1.0), Some(50)),
        ]);
        let outcome = select(
            &catalog,
            &balanced(WeightedSignals::DEFAULT, Target::Country("GB".into())),
            &latency_context(&[("id-GB#1", 100), ("id-GB#2", 100)]),
        )
        .unwrap();
        for candidate in &outcome.ranked {
            let breakdown = candidate.signals.weighted.as_ref().unwrap();
            assert_eq!(breakdown.stability_term, 0.0);
            assert_eq!(breakdown.history_term, 0.0);
        }
        // Equal load+latency inputs: the stability/history weights do
        // not perturb the order (id tiebreak decides).
        let ranked: Vec<&str> = outcome
            .ranked
            .iter()
            .map(|c| c.server.name.as_str())
            .collect();
        assert_eq!(ranked, ["GB#1", "GB#2"]);
    }

    #[test]
    fn balanced_feature_match_rewards_optional_coverage() {
        // FR-16's feature_match term: among otherwise-equal candidates
        // the one satisfying the optional features scores lower
        // (better).
        let mut with_p2p = spec_with("GB#1", "GB", Some(1.0), Some(50));
        with_p2p.features = 4;
        let catalog = build_catalog(&[with_p2p, spec_with("GB#2", "GB", Some(1.0), Some(50))]);
        let mut request = balanced(
            WeightedSignals {
                feature_match: 0.2,
                ..WeightedSignals::DEFAULT_ZEROED
            },
            Target::Country("GB".into()),
        );
        request.constraints.optional_features = vec![FeatureConstraint::P2p];
        let outcome = select(&catalog, &request, &SelectionContext::default()).unwrap();
        let ranked: Vec<&str> = outcome
            .ranked
            .iter()
            .map(|c| c.server.name.as_str())
            .collect();
        assert_eq!(ranked, ["GB#1", "GB#2"]);
        let satisfied = outcome.ranked[0].signals.weighted.unwrap();
        let unsatisfied = outcome.ranked[1].signals.weighted.unwrap();
        assert_eq!(satisfied.feature_match_term, 0.0);
        assert!((unsatisfied.feature_match_term - 0.2).abs() < 1e-6);
    }

    #[test]
    fn balanced_hand_built_invalid_weights_refuse_at_select() {
        // from_pairs validates, but a hand-built struct bypasses it;
        // select re-checks (NaN would poison every comparison).
        let catalog = build_catalog(&[spec_with("GB#1", "GB", Some(1.0), Some(50))]);
        let weights = WeightedSignals {
            load: f32::NAN,
            ..WeightedSignals::DEFAULT_ZEROED
        };
        let err = select(
            &catalog,
            &balanced(weights, Target::Country("GB".into())),
            &SelectionContext::default(),
        )
        .unwrap_err();
        assert!(matches!(err, SelectionError::InvalidWeights(_)), "{err}");
    }

    #[test]
    fn unsatisfiable_requests_carry_the_structured_report() {
        // FR-22 end-to-end through select: the error explains which
        // constraints eliminated the candidates.
        let catalog = build_catalog(&[
            Spec {
                gateway: Some("acme-corp"),
                ..Spec::new("acme-corp#1", "SE")
            },
            Spec {
                features: 4,
                ..spec_with("DE#1", "DE", Some(1.0), Some(50))
            },
        ]);
        let mut request = official(Target::Fastest);
        request.constraints.excluded_countries = vec!["DE".into()];
        let err = select(&catalog, &request, &SelectionContext::default()).unwrap_err();
        match &err {
            SelectionError::ConstraintsNotSatisfied { report } => {
                assert_eq!(stage_count(report, FilterStage::ServerType), 1);
                assert_eq!(stage_count(report, FilterStage::ExcludedCountry), 1);
                let rendered = err.to_string();
                assert!(
                    rendered.contains("no eligible server") && rendered.contains("server-type"),
                    "the Display names the eliminating stages: {rendered}"
                );
            }
            other => panic!("expected the FR-22 error, got {other}"),
        }
    }

    #[test]
    fn selection_is_deterministic_for_identical_inputs() {
        // Pure core, pinned: same catalog + request + context, same
        // order — the tiebreak discipline guarantees it.
        let catalog = build_catalog(&[
            spec_with("GB#1", "GB", Some(1.0), Some(50)),
            spec_with("GB#2", "GB", Some(1.0), Some(50)),
            spec_with("GB#3", "GB", Some(0.5), Some(99)),
        ]);
        let first = select(
            &catalog,
            &official(Target::Fastest),
            &SelectionContext::default(),
        )
        .unwrap();
        let second = select(
            &catalog,
            &official(Target::Fastest),
            &SelectionContext::default(),
        )
        .unwrap();
        fn ranked_names<'r>(outcome: &'r SelectionOutcome<'_>) -> Vec<&'r str> {
            outcome
                .ranked
                .iter()
                .map(|c| c.server.name.as_str())
                .collect()
        }
        assert_eq!(ranked_names(&first), ranked_names(&second));
    }

    // ------------------------------------------------------------------
    // Slice 4 — the 20k synthetic benchmark (the M3 normative exit:
    // selection <= 500 ms on 20k synthetic servers). Plan decision 1:
    // 20k servers = 5,000 logicals x 4 physicals each, inside the
    // landed S6 caps (16,384 logicals / 262,144 physicals — a 20k
    // LOGICAL fixture is unrepresentable). Deterministic generation:
    // a fixed-seed LCG, no wall clock, no RNG dependency.
    // ------------------------------------------------------------------

    /// A deterministic LCG with a splitmix64 output mix (test fixture
    /// generation only — never product randomness; the scheduler's
    /// jitter uses the OS CSPRNG). The mix matters: a raw LCG's low
    /// bits have tiny periods (bit 0 alternates every call), which
    /// bit-biased a first draft of this fixture into setting the
    /// Secure Core feature on 100% of "standard" logicals.
    struct Lcg(u64);

    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next_u64() % bound
        }
    }

    const BENCH_COUNTRIES: &[&str] = &[
        "AT", "BE", "BG", "CH", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB", "HR", "HU", "IE",
        "IS", "IT", "LT", "LU", "LV", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK", "US", "CA",
        "MX", "BR", "AR", "CL", "CO", "AU", "NZ", "JP", "KR", "SG", "HK", "IN", "ID", "ZA", "AE",
        "IL", "TR",
    ];

    const BENCH_LOGICALS: usize = 5_000;
    const BENCH_PHYSICALS_EACH: usize = 4;

    /// Builds the 20k-server catalog document (5,000 logicals x 4
    /// physicals = 20,000 server entries): mixed countries, tiers,
    /// feature bits, protocols, 90/5/5 online/offline/unknown logical
    /// statuses, 90% exposed loads (10% absent — real LoadNotExposed
    /// work), scores on every logical, ~2% gateways and ~5%
    /// Secure-Core-shaped entries.
    fn synthetic_catalog_20k() -> String {
        let mut rng = Lcg(0x5EED_2026_0825);
        let mut doc = String::with_capacity(8 << 20);
        doc.push_str(r#"{"Code":1000,"StatusID":"bench","LogicalServers":["#);
        for index in 0..BENCH_LOGICALS {
            if index > 0 {
                doc.push(',');
            }
            let exit = BENCH_COUNTRIES[rng.below(BENCH_COUNTRIES.len() as u64) as usize];
            let kind = rng.below(100);
            let (name, entry, gateway, mut features) = if kind < 2 {
                // Gateway logical.
                (
                    format!("bench-gw-{index}#1"),
                    exit.to_owned(),
                    format!("bench-gw-{index}"),
                    0u64,
                )
            } else if kind < 7 {
                // Secure-Core-shaped logical (entry differs from exit).
                let mut entry_index = rng.below(BENCH_COUNTRIES.len() as u64 - 1) as usize + 1; // 1..len
                if BENCH_COUNTRIES[entry_index] == exit {
                    entry_index = 0;
                }
                (
                    format!("{}-{exit}#{index}", BENCH_COUNTRIES[entry_index]),
                    BENCH_COUNTRIES[entry_index].to_owned(),
                    String::new(),
                    1u64,
                )
            } else {
                // Standard logical: non-SC capability bits only — a
                // logical carrying the Secure Core bit IS a Secure Core
                // server, not a standard one with noise.
                (
                    format!("{exit}#{index}"),
                    exit.to_owned(),
                    String::new(),
                    rng.below(32) << 1,
                )
            };
            features |= rng.below(4) & !1; // extra capability bits, SC bit never
            let tier = rng.below(4);
            let mut fields = format!(
                r#""ID":"bench-id-{index}","Name":"{name}","EntryCountry":"{entry}","ExitCountry":"{exit}","Tier":{tier},"Features":{features}"#
            );
            let status_roll = rng.below(100);
            if status_roll < 90 {
                fields.push_str(",\"Status\":1");
            } else if status_roll < 95 {
                fields.push_str(",\"Status\":0");
            } // else: absent — unknown status, fail-closed at the filter
            if rng.below(100) < 90 {
                fields.push_str(&format!(",\"Load\":{}", rng.below(101)));
            }
            fields.push_str(&format!(
                ",\"Score\":{:.3}",
                rng.below(10_000) as f32 / 1000.0
            ));
            if !gateway.is_empty() {
                fields.push_str(&format!(",\"GatewayName\":\"{gateway}\""));
            }
            let mut physicals = Vec::with_capacity(BENCH_PHYSICALS_EACH);
            for physical in 0..BENCH_PHYSICALS_EACH {
                let online = rng.below(100) < 90;
                let status = if online { 1 } else { 0 };
                let mut entry_json =
                    format!(r#""Domain":"b{index}-{physical}.example","Status":{status}"#);
                if online && rng.below(100) < 80 {
                    let protocols = match rng.below(3) {
                        0 => r#""WireGuardUDP":{"IPv4":"192.0.2.1","Ports":[443]}"#.to_owned(),
                        1 => r#""WireGuardUDP":{"IPv4":"192.0.2.1","Ports":[443]},"WireGuardTCP":{"IPv4":"192.0.2.1","Ports":[443]}"#.to_owned(),
                        _ => r#""WireGuardUDP":{"IPv4":"192.0.2.1","Ports":[443]},"WireGuardTLS":{"IPv4":"192.0.2.1","Ports":[443]}"#.to_owned(),
                    };
                    entry_json.push_str(&format!(r#","EntryPerProtocol":{{{protocols}}}"#));
                }
                physicals.push(format!("{{{entry_json}}}"));
            }
            doc.push_str(&format!(
                r#"{{{fields},"Servers":[{}]}}"#,
                physicals.join(",")
            ));
        }
        doc.push_str("]}");
        doc
    }

    #[test]
    fn selection_pipeline_on_20k_synthetic_servers_within_500ms() {
        // The M3 normative exit, as a real wall-clock assert on the
        // FULL pipeline (strict parse of the raw bytes + hard filters +
        // a load-weighted balanced ranking + the report). Margin
        // disclosure: the assert IS the normative 500 ms bar with no
        // inflation; the measured headroom on this runner is printed
        // under --nocapture and must stay generous, not sit at the bar.
        let body = synthetic_catalog_20k();
        let started = std::time::Instant::now();
        let catalog = protonwire_store::catalog::CatalogDocument::from_bytes(body.as_bytes())
            .expect("the synthetic 20k document must parse against the S6 contract");
        let parsed_after = started.elapsed();
        let request = SelectionRequest {
            target: Target::Fastest,
            policy: RankingPolicy::Balanced {
                weights: WeightedSignals {
                    load: 1.0,
                    ..WeightedSignals::DEFAULT_ZEROED
                },
            },
            constraints: Constraints::default(),
        };
        let outcome = select(&catalog, &request, &SelectionContext::default())
            .expect("the synthetic fleet must yield ranked candidates");
        let total = started.elapsed();

        // Shape pins: 20,000 server entries, 5,000 logicals, and a
        // non-trivial surviving set (the filters and the LoadNotExposed
        // policy stage both did real work).
        let physicals: usize = catalog
            .logical_servers
            .iter()
            .map(|s| s.servers.len())
            .sum();
        assert_eq!(catalog.logical_servers.len(), BENCH_LOGICALS);
        assert_eq!(physicals, 20_000, "5,000 x 4 = 20k total server entries");
        assert_eq!(outcome.report.considered(), BENCH_LOGICALS);
        assert!(
            !outcome.ranked.is_empty() && outcome.ranked.len() > 1_000,
            "an implausibly small survivor set would void the measurement: {}",
            outcome.ranked.len()
        );

        eprintln!(
            "20k benchmark: parse {:?}, select {:?}, total {:?} (bar: 500ms)",
            parsed_after,
            total - parsed_after,
            total
        );
        assert!(
            total <= Duration::from_millis(500),
            "selection pipeline on 20k synthetic servers took {total:?} (parse {parsed_after:?}); \
             the M3 exit bar is 500 ms"
        );
    }
}
