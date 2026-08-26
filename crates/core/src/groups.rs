//! Connection groups: the core-owned registry and the group-target
//! resolver (PRD 7.3B, FR-23I; M3 U2/U3).
//!
//! ## What this module is
//!
//! FR-23I: `protonwire-core` owns ONE connection-group registry,
//! generated and validated from `docs/connection-groups.yaml` by
//! `cargo xtask groups-gen`. The generated data lives in the private
//! `registry` submodule (never hand-edited; `groups-gen --check` in
//! `cargo xtask all` fails on drift, and generation itself refuses a
//! document that fails the S13 golden-table validation). Consumers —
//! CLI, TUI, GUI, the daemon, the wire — reach groups through this
//! module and never hard-code preset lists.
//!
//! [`resolve_group`] maps a group's frozen catalog definition onto the
//! pure selection core's vocabulary ([`crate::selection::Target`],
//! [`crate::selection::Constraints`],
//! [`crate::selection::RankingPolicy`]) so a group request is an
//! ordinary [`crate::selection::select`] call: `connect group
//! proton:fastest-country` and the catalog's definition of that group
//! share one code path (PRD 9.2's `group <NAMESPACED_GROUP_ID>`
//! grammar; FR-23P's filter order is the selection pipeline's own).
//!
//! ## Regional membership (FR-23N/O, T-30)
//!
//! The six `protonwire:fastest-*` groups target a primary UN M49
//! region. Membership is the generated `registry::COUNTRY_REGIONS`
//! table — country to exactly one continent, derived from the
//! vendored, checksummed `resources/geo/un-m49.csv` (generation rides
//! the `m49-verify` gate; runtime never parses the CSV). North America
//! is the composite 021+013+029 view (Northern America plus Central
//! America and the Caribbean). A country outside the mapping is
//! unmapped-and-ineligible: it belongs to no region group.

use crate::selection::ProtocolConstraint;
use crate::selection::{
    Constraints, FORBIDDEN_RANKING_SIGNALS, RankingPolicy, SelectionContext, SelectionError,
    SelectionOutcome, SelectionRequest, Target, WeightedSignals,
};
use protonwire_store::catalog::CatalogDocument;

mod registry;

/// The registry document's own provenance stamp — which catalog
/// revision produced the groups (PRD §7.3B; Codex PR#6, P2: consumers
/// report the revision instead of guessing it from source keys).
#[must_use]
pub fn catalog_revision() -> &'static str {
    registry::CATALOG_REVISION
}

/// The regional taxonomy's revision identity — the taxonomy id plus
/// the vendored M49 snapshot's source date (PRD §7.3B's "taxonomy
/// revision" arm).
#[must_use]
pub fn taxonomy_revision() -> &'static str {
    registry::TAXONOMY_REVISION
}

/// Which ecosystem a group's behavior reproduces (FR-23J: `proton:*` is
/// behavior reproduced from an official Proton selector or preset;
/// `protonwire:*` is an added group).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupOrigin {
    /// An official Proton selector/preset reproduction.
    Proton,
    /// A ProtonWire-added group.
    Protonwire,
}

impl GroupOrigin {
    /// The stable wire/status token.
    pub fn as_str(self) -> &'static str {
        match self {
            GroupOrigin::Proton => "proton",
            GroupOrigin::Protonwire => "protonwire",
        }
    }
}

/// Where the group's definition was verified against (FR-23K: a public
/// API definition when one exists, else a pinned official-client
/// compatibility revision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionSource {
    /// Defined by the public Muon/Proton API.
    ProtonApi,
    /// Verified against a pinned official-client revision.
    OfficialClientCompat,
    /// Defined by ProtonWire itself.
    Protonwire,
}

impl DefinitionSource {
    /// The stable wire/status token (the yaml vocabulary).
    pub fn as_str(self) -> &'static str {
        match self {
            DefinitionSource::ProtonApi => "proton-api",
            DefinitionSource::OfficialClientCompat => "official-client-compat",
            DefinitionSource::Protonwire => "protonwire",
        }
    }
}

/// What entitlement a group's selection needs (the daemon composes S8
/// entitlement at the selection boundary, M3 PR-4/U6 — the registry
/// carries the requirement, it does not evaluate it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupEntitlement {
    /// Availability depends on the account plan.
    PlanDependent,
    /// Availability depends on the target and the requested features.
    TargetAndFeatureDependent,
    /// Paid location selection (the regional groups).
    PaidLocationSelection,
}

impl GroupEntitlement {
    /// The stable wire/status token (the yaml vocabulary).
    pub fn as_str(self) -> &'static str {
        match self {
            GroupEntitlement::PlanDependent => "plan-dependent",
            GroupEntitlement::TargetAndFeatureDependent => "target-and-feature-dependent",
            GroupEntitlement::PaidLocationSelection => "paid-location-selection",
        }
    }
}

/// The connection type a group's target addresses (FR-23L: gateway and
/// Secure Core are other connection types). `None` on a target whose
/// kind IS the connection type (`secure-core`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// The eligible Standard fleet.
    Standard,
}

impl ConnectionType {
    /// The stable wire/status token (the yaml vocabulary).
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectionType::Standard => "standard",
        }
    }
}

/// A group's catalog-declared ranking policy (the connection-groups
/// contract's `ranking_policies` vocabulary). These are the CATALOG's
/// names; [`crate::selection::RankingPolicy`] is the executable form
/// [`resolve_group`](fn.resolve_group.html) maps them onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupRankingPolicy {
    /// Opaque catalog `Score` ascending — official Fastest semantics.
    ProtonScore,
    /// ProtonWire's weighted policy.
    Balanced,
    /// Lowest Proton-exposed load.
    Load,
    /// Lowest locally measured latency (M3 PR-3's bounded prober).
    Latency,
    /// Uniform eligible country, then uniform eligible server within it.
    RandomCountryThenServer,
}

impl GroupRankingPolicy {
    /// The stable wire/status token (the yaml vocabulary).
    pub fn as_str(self) -> &'static str {
        match self {
            GroupRankingPolicy::ProtonScore => "proton-score",
            GroupRankingPolicy::Balanced => "balanced",
            GroupRankingPolicy::Load => "load",
            GroupRankingPolicy::Latency => "latency",
            GroupRankingPolicy::RandomCountryThenServer => "random-country-then-server",
        }
    }

    /// Parses the vocabulary (used for request-time ranking overrides;
    /// the group catalog itself is validated against the same tokens).
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "proton-score" => Some(GroupRankingPolicy::ProtonScore),
            "balanced" => Some(GroupRankingPolicy::Balanced),
            "load" => Some(GroupRankingPolicy::Load),
            "latency" => Some(GroupRankingPolicy::Latency),
            "random-country-then-server" => Some(GroupRankingPolicy::RandomCountryThenServer),
            _ => None,
        }
    }
}

/// A group's target selector — exactly the five kinds the v1 catalog
/// uses, with the parameters that give each kind its meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupTarget {
    /// Fastest eligible Standard target; `exclude_physical_country`
    /// carries the "excluding my country" semantics (FR-23Q).
    Fastest {
        /// Whether the physical country is excluded.
        exclude_physical_country: bool,
    },
    /// Fastest eligible target within one country.
    FastestInCountry {
        /// ISO 3166-1 alpha-2, uppercase.
        country: &'static str,
    },
    /// Fastest eligible target within one primary UN M49 region (U3;
    /// membership from the generated `registry::COUNTRY_REGIONS` table).
    FastestInRegion {
        /// The primary region name (the taxonomy vocabulary).
        region: &'static str,
    },
    /// A random eligible target (uniform country, then uniform server;
    /// the draw policy is [`GroupRankingPolicy::RandomCountryThenServer`]).
    Random,
    /// A Secure Core entry/exit route — resolves onto the routed
    /// [`Target::SecureCore`] (M3 U4: `fastest` is any eligible
    /// country, anything else pins that side's country).
    SecureCore {
        /// The entry side (`fastest` or a country, as pinned).
        entry_country: &'static str,
        /// The exit side.
        exit_country: &'static str,
    },
}

/// One built-in connection group: the full frozen catalog definition
/// (FR-23I's "core representation must preserve at least ..." — every
/// field is generated from `docs/connection-groups.yaml`, nothing is
/// transcribed by hand).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    /// The stable namespaced ID (FR-23J).
    pub id: &'static str,
    /// The display label.
    pub label: &'static str,
    /// Which ecosystem the behavior reproduces.
    pub origin: GroupOrigin,
    /// Where the definition was verified against.
    pub definition_source: DefinitionSource,
    /// What entitlement the group needs.
    pub entitlement: GroupEntitlement,
    /// Built-ins are immutable (official definitions read-only, FR-23M).
    pub immutable: bool,
    /// The connection type the target addresses, when the kind does not
    /// imply it.
    pub connection_type: Option<ConnectionType>,
    /// The target selector.
    pub target: GroupTarget,
    /// The catalog-declared ranking policy.
    pub ranking_policy: GroupRankingPolicy,
    /// The request-time ranking overrides the catalog declares
    /// (empty on `proton:*` — official overrides are forbidden).
    pub allowed_ranking_overrides: &'static [GroupRankingPolicy],
    /// The `protocol` override, when set — the one override that is
    /// also a selection constraint (required protocol).
    pub protocol_override: Option<ProtocolConstraint>,
    /// The remaining overrides (`nat`, `lan_access`), pinned verbatim:
    /// connection-time parameters (the M4 tunnel setup), never
    /// selection filters.
    pub connection_overrides: &'static [(&'static str, &'static str)],
    /// The catalog's selection-authority annotation, when set
    /// (`proton-backend-when-required` on the random group).
    pub selection_authority: Option<&'static str>,
    /// The definition's evidence sources (top-level yaml source keys).
    pub sources: &'static [&'static str],
}

/// One primary region of the UN M49 six-continent view, with the M49
/// region codes that compose it (North America: 021+013+029).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionEntry {
    /// The region name (the taxonomy vocabulary).
    pub name: &'static str,
    /// The M49 region codes composing the region.
    pub m49_codes: &'static [&'static str],
}

/// The full built-in group catalog (generated; 14 entries in the v1
/// document — 8 `proton:*` plus 6 `protonwire:*` regional).
pub fn all_groups() -> &'static [GroupEntry] {
    registry::REGISTRY
}

/// Looks one group up by stable namespaced ID. Unknown IDs are
/// `None` — the typed never-fallback refusal for CONNECT paths lives
/// at [`resolve_group`](fn.resolve_group.html).
pub fn group(id: &str) -> Option<&'static GroupEntry> {
    registry::REGISTRY.iter().find(|entry| entry.id == id)
}

/// The six primary regions of the taxonomy (generated).
pub fn regions() -> &'static [RegionEntry] {
    registry::REGIONS
}

/// The member countries of one primary region (ISO 3166-1 alpha-2,
/// ascending); `None` when `region` is not a primary region.
pub fn region_countries(region: &str) -> Option<Vec<&'static str>> {
    regions().iter().any(|entry| entry.name == region).then(|| {
        registry::COUNTRY_REGIONS
            .iter()
            .filter(|(_, member_of)| *member_of == region)
            .map(|(iso, _)| *iso)
            .collect()
    })
}

/// The one primary region a country belongs to (FR-23O: deterministic
/// single-continent membership); `None` = unmapped (and therefore
/// ineligible for every regional group).
pub fn country_region(iso: &str) -> Option<&'static str> {
    registry::COUNTRY_REGIONS
        .iter()
        .find(|(code, _)| *code == iso)
        .map(|(_, region)| *region)
}

// --- Resolution (M3 U2) ------------------------------------------------------
//
// The resolver maps a group's frozen catalog definition onto the pure
// selection core's request vocabulary. Everything a group request
// needs flows through here — no consumer re-derives a preset.

/// FR-23Q's three physical-country sources. The resolver composes the
/// precedence; the value itself is used verbatim (non-canonical codes
/// refuse at selection, never approximated).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhysicalCountrySources<'a> {
    /// An explicit per-request country (`--physical-country GB`).
    pub explicit_request: Option<&'a str>,
    /// The explicitly configured `connection_groups.physical_country`.
    pub config: Option<&'a str>,
    /// The latest cached Proton user-location country (obtained through
    /// Muon while disconnected; S10's cache).
    pub cached_location: Option<&'a str>,
}

impl PhysicalCountrySources<'_> {
    /// The precedence FR-23Q prescribes: explicit request → explicit
    /// config → cached Muon location. `None` when no source is set.
    pub fn resolve(&self) -> Option<&str> {
        self.explicit_request
            .or(self.config)
            .or(self.cached_location)
    }
}

/// Group resolution failures — typed at the source. None of these ever
/// falls back to a different group, target, or policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GroupError {
    /// T-28: the id is not part of the canonical catalog. Never a fuzzy
    /// match, never another group's outcome.
    #[error(
        "unknown group `{id}`: not part of the canonical catalog — stable ids are the `proton:*` \
         official sets and the `protonwire:fastest-*` regional sets"
    )]
    UnknownGroup {
        /// The requested id.
        id: String,
    },
    /// T-1's every-input-schema clause, this schema's arm: a forbidden
    /// throughput signal in a ranking-override request (checked before
    /// permission — the signal ban is universal).
    #[error(
        "unsupported ranking signal `{key}`: FR-19 forbids speed/throughput ranking in every \
         input schema"
    )]
    UnsupportedRankingSignal {
        /// The rejected key.
        key: String,
    },
    /// FR-23P/T-33: official `proton:*` presets reproduce pinned
    /// semantics; a request-time ranking override would change them.
    #[error(
        "ranking override `{requested}` forbidden on `{id}`: official proton groups reproduce \
         pinned official semantics — official group ranking overrides are forbidden (FR-23P)"
    )]
    RankingOverrideForbidden {
        /// The group refusing the override.
        id: &'static str,
        /// The requested mode.
        requested: String,
    },
    /// The group's catalog entry does not declare this request-time
    /// override (regional groups declare exactly `balanced`, `load`,
    /// `latency` in the v1 catalog).
    #[error("ranking override `{requested}` is not declared by `{id}` (declared: {declared})")]
    RankingOverrideNotDeclared {
        /// The group.
        id: &'static str,
        /// The requested mode.
        requested: String,
        /// The declared override list, comma-separated.
        declared: String,
    },
    /// Declared by the catalog but not yet selectable: `latency` needs
    /// the bounded on-demand prober (M3 PR-3).
    #[error(
        "ranking policy `{requested}` on `{id}` is declared but unavailable until M3 PR-3 wires \
         the bounded on-demand latency prober"
    )]
    RankingOverrideUnavailable {
        /// The group.
        id: &'static str,
        /// The requested policy token.
        requested: String,
    },
}
/// regional override must be explicit in status).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyProvenance {
    /// The catalog's declared default policy.
    CatalogDefault,
    /// A request-time override the catalog declares for this group.
    DeclaredOverride,
}

/// A group resolved onto the selection core's request vocabulary.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedGroup {
    /// The frozen catalog definition (id, origin, entitlement,
    /// overrides — the FR-23T provenance inputs and the status
    /// surface).
    pub group: &'static GroupEntry,
    /// The selection request: feed to [`crate::selection::select`].
    pub request: SelectionRequest,
    /// How `request.policy` was chosen.
    pub policy_provenance: PolicyProvenance,
}

/// Maps a catalog ranking-policy token onto the executable policy.
/// `latency` maps onto the latency ranking policy — the observations
/// arrive via [`SelectionContext::latency`] at selection time (the
/// bounded on-demand prober's table; an empty one refuses typed
/// THERE, never a silent substitute here).
fn to_selection_policy(policy: GroupRankingPolicy) -> RankingPolicy {
    match policy {
        GroupRankingPolicy::ProtonScore => RankingPolicy::Official,
        GroupRankingPolicy::Balanced => RankingPolicy::Balanced {
            weights: WeightedSignals::DEFAULT,
        },
        GroupRankingPolicy::Load => RankingPolicy::LowestLoad,
        GroupRankingPolicy::RandomCountryThenServer => RankingPolicy::Random,
        GroupRankingPolicy::Latency => RankingPolicy::Latency,
    }
}

/// Maps one side of the yaml's Secure Core target vocabulary (`fastest`
/// or a country code) onto the routed target's `Option<String>`:
/// `fastest` is any eligible country. The generator validates presence
/// only, so a non-`fastest` token that is not a canonical country
/// refuses at selection ([`SelectionError::InvalidCountry`]) — never
/// approximated here.
fn routed_side(token: &str) -> Option<String> {
    (token != "fastest").then(|| token.to_owned())
}

/// The comma-separated declared-override list for refusal messages.
fn declared_overrides(group: &GroupEntry) -> String {
    if group.allowed_ranking_overrides.is_empty() {
        "none".to_owned()
    } else {
        group
            .allowed_ranking_overrides
            .iter()
            .map(|policy| policy.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Resolves a group request: the frozen catalog definition mapped onto
/// a [`SelectionRequest`]. `ranking_override` is the request-time
/// `--by` value (T-33's discipline: `proton:*` forbids overrides
/// outright; regional groups honor exactly their declared list).
/// `physical` carries FR-23Q's three sources — the resolver composes
/// the precedence and the selection core enforces the rest.
pub fn resolve_group(
    id: &str,
    ranking_override: Option<&str>,
    physical: &PhysicalCountrySources<'_>,
) -> Result<ResolvedGroup, GroupError> {
    let group = group(id).ok_or_else(|| GroupError::UnknownGroup { id: id.to_owned() })?;

    // T-1 discipline at this schema: the forbidden throughput signals
    // are their own class, checked before any permission question.
    if let Some(mode) = ranking_override
        && FORBIDDEN_RANKING_SIGNALS.contains(&mode)
    {
        return Err(GroupError::UnsupportedRankingSignal {
            key: mode.to_owned(),
        });
    }

    let (policy, policy_provenance) = match ranking_override {
        None => (
            to_selection_policy(group.ranking_policy),
            PolicyProvenance::CatalogDefault,
        ),
        Some(mode) => {
            if group.origin == GroupOrigin::Proton {
                return Err(GroupError::RankingOverrideForbidden {
                    id: group.id,
                    requested: mode.to_owned(),
                });
            }
            let requested = GroupRankingPolicy::parse(mode).ok_or_else(|| {
                GroupError::RankingOverrideNotDeclared {
                    id: group.id,
                    requested: mode.to_owned(),
                    declared: declared_overrides(group),
                }
            })?;
            if !group.allowed_ranking_overrides.contains(&requested) {
                return Err(GroupError::RankingOverrideNotDeclared {
                    id: group.id,
                    requested: mode.to_owned(),
                    declared: declared_overrides(group),
                });
            }
            (
                to_selection_policy(requested),
                PolicyProvenance::DeclaredOverride,
            )
        }
    };

    let mut constraints = Constraints {
        required_protocol: group.protocol_override,
        ..Constraints::default()
    };

    let target = match &group.target {
        GroupTarget::Fastest {
            exclude_physical_country,
        } => {
            constraints.exclude_physical_country = *exclude_physical_country;
            if *exclude_physical_country {
                constraints.physical_country = physical.resolve().map(str::to_owned);
            }
            Target::Fastest
        }
        GroupTarget::FastestInCountry { country } => Target::Country((*country).to_owned()),
        GroupTarget::FastestInRegion { region } => {
            // Generation asserts every declared region has members, so
            // this is total over the registry's own data.
            let countries = region_countries(region).unwrap_or_else(|| {
                unreachable!("registry guarantees membership for declared region `{region}`")
            });
            Target::Countries(countries.into_iter().map(str::to_owned).collect())
        }
        GroupTarget::Random => Target::Fastest,
        GroupTarget::SecureCore {
            entry_country,
            exit_country,
        } => Target::SecureCore {
            entry_country: routed_side(entry_country),
            exit_country: routed_side(exit_country),
        },
    };

    Ok(ResolvedGroup {
        group,
        request: SelectionRequest {
            target,
            policy,
            constraints,
        },
        policy_provenance,
    })
}

/// The composed group entry point: resolve, then select, in one call.
/// The daemon/CLI boundary (M3 PR-4) calls this; the split errors stay
/// distinguishable for exit-code mapping.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum GroupSelectionError {
    /// Resolution refused (unknown group, override discipline).
    #[error(transparent)]
    Group(#[from] GroupError),
    /// Selection refused (the FR-22 report, FR-23Q/FR-23H typed
    /// refusals, policy refusals).
    #[error(transparent)]
    Selection(#[from] SelectionError),
}

/// Resolves and selects in one call over the cached catalog (FR-23R:
/// no network — the catalog bytes are the daemon's cached document).
pub fn select_group<'a>(
    catalog: &'a CatalogDocument,
    id: &str,
    ranking_override: Option<&str>,
    physical: &PhysicalCountrySources<'_>,
    context: &SelectionContext,
) -> Result<SelectionOutcome<'a>, GroupSelectionError> {
    let resolved = resolve_group(id, ranking_override, physical)?;
    Ok(crate::selection::select(
        catalog,
        &resolved.request,
        context,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The v1 catalog's canonical id set — the registry must carry
    /// exactly these groups, no more, no fewer (T-28).
    const CANONICAL_IDS: [&str; 14] = [
        "proton:anti-censorship",
        "proton:fastest-country",
        "proton:fastest-excluding-my-country",
        "proton:gaming",
        "proton:max-security",
        "proton:random-country",
        "proton:streaming-us",
        "proton:work-school",
        "protonwire:fastest-africa",
        "protonwire:fastest-asia",
        "protonwire:fastest-europe",
        "protonwire:fastest-north-america",
        "protonwire:fastest-oceania",
        "protonwire:fastest-south-america",
    ];

    #[test]
    fn the_registry_carries_exactly_the_canonical_groups() {
        // T-28: every named group resolves — the generated registry is
        // the complete canonical catalog, not a subset.
        let mut ids: Vec<&str> = all_groups().iter().map(|g| g.id).collect();
        ids.sort_unstable();
        let mut expected = CANONICAL_IDS;
        expected.sort_unstable();
        assert_eq!(ids, expected, "the registry must be the canonical 14");
        for id in CANONICAL_IDS {
            let entry = group(id).unwrap_or_else(|| panic!("`{id}` must resolve"));
            assert_eq!(entry.id, id);
        }
    }

    /// Codex PR#6 (P2), PRD §7.3B: the registry PRESERVES the source
    /// document's provenance — the catalog revision and the taxonomy
    /// revision are runtime-visible, so consumers report which
    /// revision produced a group instead of guessing from source
    /// keys. The freshness gate (`groups-gen --check` in `xtask all`)
    /// pins the VALUES against the yaml: a revision change forces
    /// regeneration or fails CI.
    #[test]
    fn the_registry_preserves_the_source_revisions() {
        let catalog = catalog_revision();
        let taxonomy = taxonomy_revision();
        assert!(
            !catalog.trim().is_empty(),
            "the catalog revision must be carried, never elided"
        );
        assert!(
            taxonomy.contains('@'),
            "the taxonomy revision names the taxonomy id and its snapshot date: {taxonomy}"
        );
        assert!(
            taxonomy.starts_with("un-m49-six-continent-view@"),
            "the current taxonomy identity: {taxonomy}"
        );
    }

    #[test]
    fn unknown_group_lookups_return_none() {
        // T-28's refusal half: nothing invents a group — not a
        // namespace-valid unknown id, not a prefix, not junk.
        for unknown in [
            "proton:atlantis",
            "protonwire:fastest-antarctica",
            "fastest-country",
            "proton:",
            "",
        ] {
            assert!(group(unknown).is_none(), "`{unknown}` must not resolve");
        }
    }

    /// T-28: immutable, namespaced, unique built-in definitions.
    #[test]
    fn built_ins_are_immutable_namespaced_and_unique() {
        let mut seen = BTreeSet::new();
        for entry in all_groups() {
            assert!(
                entry.immutable,
                "{}: built-in definitions are immutable (FR-23M)",
                entry.id
            );
            assert_eq!(
                entry.id.split(':').next(),
                Some(entry.origin.as_str()),
                "{}: the id namespace must match the recorded origin",
                entry.id
            );
            assert!(seen.insert(entry.id), "{}: duplicate id", entry.id);
        }
    }

    /// T-30: the six primary regions with the taxonomy's M49 codes —
    /// including North America's composite 021+013+029 composition.
    #[test]
    fn the_six_primary_regions_and_their_composition_are_pinned() {
        let regions = regions();
        assert_eq!(regions.len(), 6, "the six-continent view");
        let by_name = |name: &str| {
            regions
                .iter()
                .find(|r| r.name == name)
                .unwrap_or_else(|| panic!("region `{name}` missing"))
        };
        let mut sorted: Vec<&str> = regions.iter().map(|r| r.name).collect();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            [
                "africa",
                "asia",
                "europe",
                "north-america",
                "oceania",
                "south-america"
            ],
        );
        assert_eq!(by_name("africa").m49_codes, &["002"]);
        assert_eq!(by_name("asia").m49_codes, &["142"]);
        assert_eq!(by_name("europe").m49_codes, &["150"]);
        // The composite: Northern America plus Central America and the
        // Caribbean (FR-23N's table names all three).
        let mut na = by_name("north-america").m49_codes.to_vec();
        na.sort_unstable();
        assert_eq!(na, ["013", "021", "029"]);
        assert_eq!(by_name("south-america").m49_codes, &["005"]);
        assert_eq!(by_name("oceania").m49_codes, &["009"]);
    }

    /// T-30: deterministic single-continent membership — every country
    /// in the generated mapping appears exactly once, the regional
    /// groups partition the mapped world, and the membership counts
    /// match the vendored snapshot's documented distribution (the M1
    /// pin: africa 60, asia 50, europe 51, north-america 41,
    /// south-america 16, oceania 29).
    #[test]
    fn every_country_maps_to_exactly_one_region() {
        let mut seen = BTreeSet::new();
        for (iso, region) in registry::COUNTRY_REGIONS {
            assert_eq!(iso.len(), 2, "`{iso}` must be ISO alpha-2");
            assert!(
                iso.bytes().all(|b| b.is_ascii_uppercase()),
                "`{iso}` must be uppercase"
            );
            assert!(
                regions().iter().any(|r| r.name == *region),
                "`{iso}` maps to unknown region `{region}`"
            );
            assert!(
                seen.insert(*iso),
                "`{iso}` mapped twice — one continent only"
            );
        }
        assert_eq!(seen.len(), 247, "the vendored snapshot carries 247 rows");

        let mut counts = std::collections::BTreeMap::new();
        for region in regions() {
            let members = region_countries(region.name)
                .unwrap_or_else(|| panic!("`{}` must be a primary region", region.name));
            assert!(!members.is_empty(), "{} has no members", region.name);
            counts.insert(region.name, members.len());
        }
        assert_eq!(counts.get("africa"), Some(&60));
        assert_eq!(counts.get("asia"), Some(&50));
        assert_eq!(counts.get("europe"), Some(&51));
        assert_eq!(counts.get("north-america"), Some(&41));
        assert_eq!(counts.get("south-america"), Some(&16));
        assert_eq!(counts.get("oceania"), Some(&29));
    }

    /// T-30's composite probe: the three M49 sub-regions of North
    /// America each contribute members — US (021), MX (013), JM (029)
    /// all resolve to `north-america` and to no other region.
    #[test]
    fn north_america_membership_spans_all_three_composite_codes() {
        for iso in ["US", "MX", "JM"] {
            assert_eq!(country_region(iso), Some("north-america"), "`{iso}`");
        }
        // And no double membership: a country of another region never
        // answers for north-america.
        assert_eq!(country_region("GB"), Some("europe"));
        assert_eq!(country_region("JP"), Some("asia"));
        assert_eq!(country_region("BR"), Some("south-america"));
        assert_eq!(country_region("AU"), Some("oceania"));
        assert_eq!(country_region("ZA"), Some("africa"));
    }

    /// T-30: unknown-country handling — a country outside the vendored
    /// mapping is unmapped, hence ineligible for every regional group.
    #[test]
    fn unmapped_countries_belong_to_no_region() {
        // User-assigned ISO codes the UN M49 snapshot does not carry.
        for unmapped in ["XX", "ZZ", "QX"] {
            assert_eq!(country_region(unmapped), None, "`{unmapped}`");
            for region in regions() {
                assert!(
                    !region_countries(region.name).unwrap().contains(&unmapped),
                    "`{unmapped}` must not be a member of {}",
                    region.name
                );
            }
        }
    }

    /// region_countries refuses unknown region names (typed, not empty).
    #[test]
    fn region_countries_refuses_unknown_regions() {
        assert!(region_countries("atlantis").is_none());
        assert_eq!(
            region_countries("europe").unwrap().first(),
            Some(&"AD"),
            "members arrive in ascending ISO order"
        );
    }

    // --- Resolution (M3 U2): T-28's typed refusal, T-33's ranking
    // discipline, FR-23Q's physical-country precedence, T-29's pinned
    // official semantics, T-30's regional selection. -------------------------

    use crate::selection::{
        ProtocolConstraint, RankingPolicy, SelectionContext, SelectionError, Target,
    };

    fn resolve(id: &str) -> Result<ResolvedGroup, GroupError> {
        resolve_group(id, None, &PhysicalCountrySources::default())
    }

    /// T-28: the canonical catalog resolves — every group maps onto
    /// selection parameters; `proton:max-security` resolves the ROUTED
    /// Secure Core target (U4): the yaml's `fastest`/`fastest` becomes
    /// the any/any pair over the Secure Core fleet.
    #[test]
    fn every_canonical_group_resolves() {
        for entry in all_groups() {
            let resolved = resolve(entry.id).unwrap_or_else(|e| panic!("{}: {e}", entry.id));
            assert_eq!(resolved.group.id, entry.id);
        }
        let max_security = group("proton:max-security").expect("the definition stays available");
        assert_eq!(
            max_security.target,
            GroupTarget::SecureCore {
                entry_country: "fastest",
                exit_country: "fastest"
            }
        );
        let resolved = resolve("proton:max-security").unwrap();
        assert_eq!(
            resolved.request.target,
            Target::SecureCore {
                entry_country: None,
                exit_country: None
            },
            "the yaml's `fastest` maps onto the routed side's any"
        );
        assert_eq!(resolved.request.policy, RankingPolicy::Official);
        assert_eq!(
            max_security.connection_overrides,
            &[("lan_access", "block")],
            "the lan_access override rides the definition (connection-time, M4)"
        );
    }

    /// T-28's refusal half at the CONNECT path: an unknown id is the
    /// typed refusal naming the id — never a fuzzy match, never another
    /// group's outcome.
    #[test]
    fn unknown_group_is_the_typed_refusal_never_a_fallback() {
        for unknown in [
            "proton:atlantis",
            "protonwire:fastest-antarctica",
            "fastest-country",
        ] {
            let err = resolve(unknown).unwrap_err();
            assert_eq!(
                err,
                GroupError::UnknownGroup {
                    id: unknown.to_owned()
                },
                "`{unknown}` must be the typed unknown-group refusal"
            );
            assert!(
                err.to_string().contains(unknown),
                "the refusal names the id: {err}"
            );
        }
    }

    /// T-33: official groups rank by Proton score and REJECT request-time
    /// ranking overrides — the refusal is its own class, citing FR-23P.
    #[test]
    fn official_groups_rank_by_proton_score_and_reject_overrides() {
        for id in [
            "proton:fastest-country",
            "proton:fastest-excluding-my-country",
            "proton:streaming-us",
            "proton:gaming",
            "proton:anti-censorship",
            "proton:work-school",
        ] {
            let resolved = resolve(id).unwrap();
            assert_eq!(resolved.request.policy, RankingPolicy::Official, "{id}");
            assert_eq!(
                resolved.policy_provenance,
                PolicyProvenance::CatalogDefault,
                "{id}"
            );
            for mode in ["official", "balanced", "load"] {
                let err =
                    resolve_group(id, Some(mode), &PhysicalCountrySources::default()).unwrap_err();
                assert_eq!(
                    err,
                    GroupError::RankingOverrideForbidden {
                        id,
                        requested: mode.to_owned(),
                    },
                    "{id} + `--by {mode}`: official semantics are immutable (FR-23P)"
                );
                assert!(
                    err.to_string().contains("FR-23P"),
                    "the refusal cites the rule: {err}"
                );
            }
        }
    }

    /// T-33: the random group's official semantics ARE the two-level
    /// draw (the catalog declares `random-country-then-server`, not
    /// proton-score) — and it rejects overrides like every proton:*.
    #[test]
    fn random_country_resolves_the_random_policy() {
        let resolved = resolve("proton:random-country").unwrap();
        assert_eq!(resolved.request.policy, RankingPolicy::Random);
        assert_eq!(resolved.request.target, Target::Fastest);
        assert_eq!(
            resolved.group.selection_authority,
            Some("proton-backend-when-required"),
            "the authority annotation rides the definition (FR-23G's backend-authorized \
             changes are the daemon boundary's to honor)"
        );
        let err = resolve_group(
            "proton:random-country",
            Some("load"),
            &PhysicalCountrySources::default(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            GroupError::RankingOverrideForbidden {
                id: "proton:random-country",
                requested: "load".to_owned(),
            }
        );
    }

    /// T-1/T-33: the forbidden throughput signals are their OWN class on
    /// this schema too, and outrank the permission questions — a `speed`
    /// override on a proton group is the signal rejection, not the
    /// (also-true) forbidden-override rejection.
    #[test]
    fn speed_overrides_are_the_signal_rejection_on_both_namespaces() {
        for id in ["proton:fastest-country", "protonwire:fastest-europe"] {
            for signal in ["speed", "estimated-throughput"] {
                let err = resolve_group(id, Some(signal), &PhysicalCountrySources::default())
                    .unwrap_err();
                assert_eq!(
                    err,
                    GroupError::UnsupportedRankingSignal {
                        key: signal.to_owned()
                    },
                    "{id} + `{signal}`"
                );
                assert!(
                    err.to_string().contains("FR-19"),
                    "the refusal cites the rule: {err}"
                );
            }
        }
    }

    /// T-33: regional groups default to Proton score.
    #[test]
    fn regional_groups_default_to_proton_score() {
        for entry in all_groups()
            .iter()
            .filter(|e| e.origin == GroupOrigin::Protonwire)
        {
            let resolved = resolve(entry.id).unwrap();
            assert_eq!(
                resolved.request.policy,
                RankingPolicy::Official,
                "{}",
                entry.id
            );
            assert_eq!(
                resolved.policy_provenance,
                PolicyProvenance::CatalogDefault,
                "{}",
                entry.id
            );
        }
    }

    /// T-33: declared regional overrides apply and are explicit in the
    /// resolution (status-visible); undeclared ones refuse naming the
    /// declared list; latency is declared and real since U5.
    #[test]
    fn regional_declared_overrides_apply_and_undeclared_refuse() {
        let load = resolve_group(
            "protonwire:fastest-europe",
            Some("load"),
            &PhysicalCountrySources::default(),
        )
        .unwrap();
        assert_eq!(load.request.policy, RankingPolicy::LowestLoad);
        assert_eq!(load.policy_provenance, PolicyProvenance::DeclaredOverride);

        let balanced = resolve_group(
            "protonwire:fastest-europe",
            Some("balanced"),
            &PhysicalCountrySources::default(),
        )
        .unwrap();
        assert_eq!(
            balanced.request.policy,
            RankingPolicy::Balanced {
                weights: crate::selection::WeightedSignals::DEFAULT
            }
        );
        assert_eq!(
            balanced.policy_provenance,
            PolicyProvenance::DeclaredOverride
        );

        for undeclared in ["official", "cheapest"] {
            let err = resolve_group(
                "protonwire:fastest-europe",
                Some(undeclared),
                &PhysicalCountrySources::default(),
            )
            .unwrap_err();
            assert_eq!(
                err,
                GroupError::RankingOverrideNotDeclared {
                    id: "protonwire:fastest-europe",
                    requested: undeclared.to_owned(),
                    declared: "balanced, load, latency".to_owned(),
                },
                "`{undeclared}`: only the catalog-declared list applies (the proton-score \
                 default is what no-override means)"
            );
        }

        let err = resolve_group(
            "protonwire:fastest-europe",
            Some("latency"),
            &PhysicalCountrySources::default(),
        )
        .unwrap();
        assert_eq!(err.request.policy, RankingPolicy::Latency);
        assert_eq!(err.policy_provenance, PolicyProvenance::DeclaredOverride);
    }

    /// FR-23Q: explicit request → explicit config → cached Muon
    /// location; no source → none.
    #[test]
    fn physical_country_precedence_follows_fr23q() {
        let all = PhysicalCountrySources {
            explicit_request: Some("DE"),
            config: Some("GB"),
            cached_location: Some("US"),
        };
        assert_eq!(all.resolve(), Some("DE"));
        assert_eq!(
            PhysicalCountrySources {
                explicit_request: None,
                config: Some("GB"),
                cached_location: Some("US"),
            }
            .resolve(),
            Some("GB")
        );
        assert_eq!(
            PhysicalCountrySources {
                explicit_request: None,
                config: None,
                cached_location: Some("US"),
            }
            .resolve(),
            Some("US")
        );
        assert_eq!(PhysicalCountrySources::default().resolve(), None);
    }

    /// T-29/FR-23Q: the excluding group resolves the composed country
    /// into its constraints; without any source the constraint stays
    /// unset and selection refuses `physical-country-required` (U1's
    /// typed refusal, reached through the composed path).
    #[test]
    fn fastest_excluding_resolves_the_physical_country_into_constraints() {
        let sources = PhysicalCountrySources {
            explicit_request: Some("GB"),
            config: Some("DE"),
            cached_location: None,
        };
        let resolved =
            resolve_group("proton:fastest-excluding-my-country", None, &sources).unwrap();
        assert!(resolved.request.constraints.exclude_physical_country);
        assert_eq!(
            resolved.request.constraints.physical_country,
            Some("GB".into())
        );

        let none = resolve_group(
            "proton:fastest-excluding-my-country",
            None,
            &PhysicalCountrySources::default(),
        )
        .unwrap();
        assert_eq!(none.request.constraints.physical_country, None);
    }

    /// T-29's per-group resolution pins: country + protocol (streaming),
    /// the stealth pair (anti-censorship/work-school), and gaming's NAT
    /// override as connection-time DATA, never a selection filter.
    #[test]
    fn the_official_presets_resolve_their_pinned_semantics() {
        let streaming = resolve("proton:streaming-us").unwrap();
        assert_eq!(streaming.request.target, Target::Country("US".to_owned()));
        assert_eq!(
            streaming.request.constraints.required_protocol,
            Some(ProtocolConstraint::WireguardUdp)
        );

        let anti = resolve("proton:anti-censorship").unwrap();
        assert_eq!(anti.request.target, Target::Fastest);
        assert!(anti.request.constraints.exclude_physical_country);
        assert_eq!(
            anti.request.constraints.required_protocol,
            Some(ProtocolConstraint::Stealth)
        );

        let work = resolve("proton:work-school").unwrap();
        assert!(!work.request.constraints.exclude_physical_country);
        assert_eq!(
            work.request.constraints.required_protocol,
            Some(ProtocolConstraint::Stealth)
        );
        assert_eq!(work.group.connection_overrides, &[("lan_access", "block")]);

        let gaming = resolve("proton:gaming").unwrap();
        assert_eq!(
            gaming.request.constraints.required_protocol, None,
            "NAT is a connection-time request (M4), never a selection filter"
        );
        assert_eq!(gaming.group.connection_overrides, &[("nat", "moderate")]);
    }

    /// T-30: regional groups resolve to their membership country sets —
    /// the composite North America carries US (021), MX (013), JM (029)
    /// and nothing from other regions.
    #[test]
    fn regional_targets_resolve_to_their_membership_country_sets() {
        let europe = resolve("protonwire:fastest-europe").unwrap();
        match &europe.request.target {
            Target::Countries(codes) => {
                for member in ["GB", "DE", "FR", "CH"] {
                    assert!(codes.contains(&member.to_owned()), "{member} ∈ europe");
                }
                for outsider in ["US", "JP", "BR", "AU", "ZA"] {
                    assert!(!codes.contains(&outsider.to_owned()), "{outsider} ∉ europe");
                }
            }
            other => panic!("europe resolves to a country set, got {other:?}"),
        }
        let north_america = resolve("protonwire:fastest-north-america").unwrap();
        match &north_america.request.target {
            Target::Countries(codes) => {
                for member in ["US", "MX", "JM", "CA"] {
                    assert!(
                        codes.contains(&member.to_owned()),
                        "{member} ∈ north-america"
                    );
                }
                assert!(!codes.contains(&"GB".to_owned()));
            }
            other => panic!("north-america resolves to a country set, got {other:?}"),
        }
    }

    // --- Selection through the composed entry point (T-29/T-30
    // end-to-end against a fixture catalog). --------------------------------

    /// A minimal S6-shaped catalog: online Standard logicals, every
    /// physical carrying UDP+TLS maps (the `udp = false` arm carries
    /// TLS only — the streaming pin needs a UDP-less US server).
    fn fixture_catalog(specs: &[(&str, &str, f32, bool)]) -> CatalogDocument {
        let servers: Vec<String> = specs
            .iter()
            .map(|(name, exit, score, udp)| {
                let maps = if *udp {
                    r#""WireGuardUDP":{"IPv4":"192.0.2.1","Ports":[443]},"WireGuardTLS":{"IPv4":"192.0.2.1","Ports":[443]}"#
                } else {
                    r#""WireGuardTLS":{"IPv4":"192.0.2.1","Ports":[443]}"#
                };
                format!(
                    r#"{{"ID":"id-{name}","Name":"{name}","EntryCountry":"{exit}","ExitCountry":"{exit}","Tier":2,"Features":0,"Status":1,"Load":20,"Score":{score},"Servers":[{{"Domain":"p0.example","Status":1,"EntryPerProtocol":{{{maps}}}}}]}}"#
                )
            })
            .collect();
        let body = format!(
            r#"{{"Code":1000,"StatusID":"t","LogicalServers":[{}]}}"#,
            servers.join(",")
        );
        CatalogDocument::from_bytes(body.as_bytes())
            .unwrap_or_else(|e| panic!("fixture catalog must parse: {e}"))
    }

    fn sources(country: Option<&'static str>) -> PhysicalCountrySources<'static> {
        PhysicalCountrySources {
            explicit_request: country,
            config: None,
            cached_location: None,
        }
    }

    #[test]
    fn fastest_country_selects_official_order() {
        // T-29: Fastest = official semantics — lowest Proton score wins.
        let catalog = fixture_catalog(&[
            ("GB#1", "GB", 1.5, true),
            ("DE#1", "DE", 0.5, true),
            ("US#1", "US", 2.5, true),
        ]);
        let outcome = select_group(
            &catalog,
            "proton:fastest-country",
            None,
            &sources(None),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(outcome.ranked[0].server.name, "DE#1");
    }

    #[test]
    fn fastest_excluding_my_country_selects_away_from_the_physical_country() {
        let catalog = fixture_catalog(&[
            ("GB#1", "GB", 0.2, true),
            ("DE#1", "DE", 1.0, true),
            ("CH#1", "CH", 2.0, true),
        ]);
        let outcome = select_group(
            &catalog,
            "proton:fastest-excluding-my-country",
            None,
            &sources(Some("GB")),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(outcome.ranked[0].server.name, "DE#1");
        assert!(
            outcome.ranked.iter().all(|c| c.server.exit_country != "GB"),
            "the physical country never wins under the exclusion"
        );

        // No source anywhere: FR-23Q's typed refusal through the
        // composed path — it must not connect without the exclusion.
        let err = select_group(
            &catalog,
            "proton:fastest-excluding-my-country",
            None,
            &sources(None),
            &SelectionContext::default(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            GroupSelectionError::Selection(SelectionError::PhysicalCountryRequired)
        );
    }

    #[test]
    fn a_non_canonical_physical_country_source_refuses_never_approximates() {
        let catalog = fixture_catalog(&[("GB#1", "GB", 1.0, true)]);
        let err = select_group(
            &catalog,
            "proton:fastest-excluding-my-country",
            None,
            &sources(Some("gb")),
            &SelectionContext::default(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            GroupSelectionError::Selection(SelectionError::InvalidCountry("gb".to_owned()))
        );
    }

    /// T-30 end-to-end: regional selection stays inside the membership —
    /// the composite North America selects across US+MX+JM while Europe
    /// excludes all of them; an unmapped catalog country is ineligible
    /// for every region.
    #[test]
    fn regional_groups_select_within_their_membership() {
        let catalog = fixture_catalog(&[
            ("US#1", "US", 3.0, true),
            ("MX#1", "MX", 1.0, true),
            ("JM#1", "JM", 2.0, true),
            ("GB#1", "GB", 0.1, true),
            ("DE#1", "DE", 0.2, true),
            ("XX#1", "XX", 0.01, true), // ISO user-assigned: in no region
        ]);
        let north_america = select_group(
            &catalog,
            "protonwire:fastest-north-america",
            None,
            &sources(None),
            &SelectionContext::default(),
        )
        .unwrap();
        let ranked: Vec<&str> = north_america
            .ranked
            .iter()
            .map(|c| c.server.name.as_str())
            .collect();
        assert_eq!(
            ranked,
            ["MX#1", "JM#1", "US#1"],
            "all three composite members"
        );

        let europe = select_group(
            &catalog,
            "protonwire:fastest-europe",
            None,
            &sources(None),
            &SelectionContext::default(),
        )
        .unwrap();
        let ranked: Vec<&str> = europe
            .ranked
            .iter()
            .map(|c| c.server.name.as_str())
            .collect();
        assert_eq!(ranked, ["GB#1", "DE#1"]);
        assert!(
            !ranked.contains(&"XX#1"),
            "an unmapped country is ineligible for every regional group (T-30)"
        );
    }

    /// T-30: the declared `load` override changes the regional order and
    /// the resolution reports the override provenance (status-visible).
    #[test]
    fn regional_load_override_selects_by_load() {
        let catalog = fixture_catalog(&[
            ("GB#1", "GB", 0.1, true), // best score
            ("DE#1", "DE", 5.0, true), // worst score
        ]);
        let outcome = select_group(
            &catalog,
            "protonwire:fastest-europe",
            Some("load"),
            &sources(None),
            &SelectionContext::default(),
        )
        .unwrap();
        // Identical loads: the id tiebreak orders them; the pin is that
        // the override applied (both survive; the policy is LowestLoad).
        assert_eq!(outcome.ranked.len(), 2);
        let resolved = resolve_group(
            "protonwire:fastest-europe",
            Some("load"),
            &PhysicalCountrySources::default(),
        )
        .unwrap();
        assert_eq!(
            resolved.policy_provenance,
            PolicyProvenance::DeclaredOverride
        );
    }

    /// T-29: streaming-us selects the fastest US server WITH WireGuard
    /// UDP — a UDP-less US server is eliminated at protocol
    /// compatibility, not silently selected.
    #[test]
    fn streaming_us_requires_wireguard_udp() {
        let catalog = fixture_catalog(&[
            ("US#1", "US", 0.1, false), // best score, no UDP map
            ("US#2", "US", 1.0, true),
            ("GB#1", "GB", 0.05, true),
        ]);
        let outcome = select_group(
            &catalog,
            "proton:streaming-us",
            None,
            &sources(None),
            &SelectionContext::default(),
        )
        .unwrap();
        assert_eq!(outcome.ranked[0].server.name, "US#2");
        let ranked: Vec<&str> = outcome
            .ranked
            .iter()
            .map(|c| c.server.name.as_str())
            .collect();
        assert_eq!(ranked, &["US#2"], "US#1 falls at protocol compatibility");
    }

    /// T-29: the random group draws through the same composed path —
    /// deterministic per seed, always inside the eligible set, and the
    /// typed entropy refusal without any.
    #[test]
    fn random_country_selects_through_the_composed_path() {
        let catalog = fixture_catalog(&[
            ("GB#1", "GB", 1.0, true),
            ("DE#1", "DE", 1.0, true),
            ("US#1", "US", 1.0, true),
        ]);
        let context = SelectionContext {
            random_entropy: Some(9),
            ..SelectionContext::default()
        };
        let first = select_group(
            &catalog,
            "proton:random-country",
            None,
            &sources(None),
            &context,
        )
        .unwrap();
        let second = select_group(
            &catalog,
            "proton:random-country",
            None,
            &sources(None),
            &context,
        )
        .unwrap();
        assert_eq!(
            first
                .ranked
                .iter()
                .map(|c| c.server.name.as_str())
                .collect::<Vec<_>>(),
            second
                .ranked
                .iter()
                .map(|c| c.server.name.as_str())
                .collect::<Vec<_>>(),
            "same entropy, same draw"
        );

        let err = select_group(
            &catalog,
            "proton:random-country",
            None,
            &sources(None),
            &SelectionContext::default(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            GroupSelectionError::Selection(SelectionError::RandomEntropyRequired)
        );
    }

    /// T-11 through the composed path: the max-security group selects
    /// the Secure Core fleet — every ranked candidate is a route
    /// (entry ≠ exit), the Standard logical never leaks in, and the
    /// official policy orders the routes by Proton score.
    #[test]
    fn max_security_selects_the_secure_core_fleet() {
        let logical = |name: &str, entry: &str, exit: &str, features: u64, score: f32| {
            format!(
                r#"{{"ID":"id-{name}","Name":"{name}","EntryCountry":"{entry}","ExitCountry":"{exit}","Tier":2,"Features":{features},"Status":1,"Load":20,"Score":{score},"Servers":[{{"Domain":"p0.example","Status":1,"EntryPerProtocol":{{"WireGuardUDP":{{"IPv4":"192.0.2.1","Ports":[443]}}}}}}]}}"#
            )
        };
        let body = format!(
            r#"{{"Code":1000,"StatusID":"t","LogicalServers":[{},{},{}]}}"#,
            logical("IS-SE#1", "IS", "SE", 1, 1.5),
            logical("CH-SE#1", "CH", "SE", 1, 0.5),
            logical("GB#1", "GB", "GB", 0, 0.1), // Standard: best score, wrong fleet
        );
        let catalog = CatalogDocument::from_bytes(body.as_bytes())
            .unwrap_or_else(|e| panic!("fixture catalog must parse: {e}"));
        let outcome = select_group(
            &catalog,
            "proton:max-security",
            None,
            &sources(None),
            &SelectionContext::default(),
        )
        .unwrap();
        let ranked: Vec<&str> = outcome
            .ranked
            .iter()
            .map(|c| c.server.name.as_str())
            .collect();
        assert_eq!(ranked, ["CH-SE#1", "IS-SE#1"]);
        assert!(
            outcome
                .ranked
                .iter()
                .all(|c| c.server.entry_country != c.server.exit_country)
        );
    }
}
