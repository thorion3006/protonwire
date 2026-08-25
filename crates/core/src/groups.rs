//! Connection groups: the core-owned registry and the group-target
//! resolver (PRD 7.3B, FR-23I; M3 U2/U3).
//!
//! ## What this module is
//!
//! FR-23I: `protonwire-core` owns ONE connection-group registry,
//! generated and validated from `docs/connection-groups.yaml` by
//! `cargo xtask groups-gen`. The generated data lives in
//! [`registry`] (never hand-edited; `groups-gen --check` in
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
//! region. Membership is the generated [`registry::COUNTRY_REGIONS`]
//! table — country to exactly one continent, derived from the
//! vendored, checksummed `resources/geo/un-m49.csv` (generation rides
//! the `m49-verify` gate; runtime never parses the CSV). North America
//! is the composite 021+013+029 view (Northern America plus Central
//! America and the Caribbean). A country outside the mapping is
//! unmapped-and-ineligible: it belongs to no region group.

use crate::selection::ProtocolConstraint;

mod registry;

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
    /// membership from [`registry::COUNTRY_REGIONS`]).
    FastestInRegion {
        /// The primary region name (the taxonomy vocabulary).
        region: &'static str,
    },
    /// A random eligible target (uniform country, then uniform server;
    /// the draw policy is [`GroupRankingPolicy::RandomCountryThenServer`]).
    Random,
    /// A Secure Core entry/exit route — delegates to the Secure Core
    /// routing unit (M3 PR-3/U4).
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
}
