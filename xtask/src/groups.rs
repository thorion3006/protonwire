//! `cargo xtask groups-validate` — validates `docs/connection-groups.yaml`
//! (schema version 1) against the connection-groups contract: the ranking
//! signal vocabulary, the physical-country policy, the regional taxonomy, and
//! the built-in group catalog (immutability, namespaces, override bounds).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::{Reporter, expect_value};

const REQUIRED_CLIENT_SURFACES: [&str; 3] = ["cli", "tui", "gui"];
const ALLOWED_RANKING_SIGNALS: &[&str] = &[
    "proton-score",
    "load",
    "measured-latency",
    "stability",
    "feature-match",
    "history",
];
const REQUIRED_FORBIDDEN_SIGNALS: &[&str] = &["estimated-speed", "estimated-throughput"];
const REQUIRED_RANKING_POLICIES: &[&str] = &[
    "proton-score",
    "balanced",
    "load",
    "latency",
    "random-country-then-server",
];
const REGIONAL_RANKING_OVERRIDES: &[&str] = &["proton-score", "balanced", "load", "latency"];

const EXPECTED_REGIONS: &[(&str, &[&str])] = &[
    ("africa", &["002"]),
    ("asia", &["142"]),
    ("europe", &["150"]),
    ("north-america", &["021", "013", "029"]),
    ("south-america", &["005"]),
    ("oceania", &["009"]),
];

const ALLOWED_DEFINITION_SOURCES: &[&str] = &["proton-api", "official-client-compat", "protonwire"];

/// Bounded vocabulary for profile/group override keys.
const ALLOWED_OVERRIDE_KEYS: &[&str] = &[
    "protocol",
    "nat",
    "lan_access",
    "entry_country",
    "exit_country",
    "exclude_physical_country",
    "connection_type",
    "selection_authority",
];

const EXPECTED_GROUP_COUNT: usize = 14;

/// The v1 catalog's canonical id set (docs/connection-groups.yaml): 8
/// `proton:*` official groups plus 6 `protonwire:*` regional fastest groups.
/// The count check alone would let a renamed entry through, so the set
/// itself is pinned against schema-version-1 documents.
const EXPECTED_GROUP_IDS: [&str; EXPECTED_GROUP_COUNT] = [
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

/// The v1 catalog's `target.kind` vocabulary: exactly the kinds the
/// canonical document uses (docs/connection-groups.yaml) — `fastest` (5
/// official groups), `random`, `fastest-in-country`, `secure-core`, and
/// `fastest-in-region` (all 6 regional groups).
const ALLOWED_TARGET_KINDS: &[&str] = &[
    "fastest",
    "fastest-in-country",
    "fastest-in-region",
    "random",
    "secure-core",
];

/// Per-canonical-group `target.kind` map, pinning each id's selection
/// semantics the way [`EXPECTED_GROUP_IDS`] pins the id set: a kind edit
/// must be a deliberate contract change, not silent drift.
const EXPECTED_GROUP_TARGET_KINDS: [(&str, &str); EXPECTED_GROUP_COUNT] = [
    ("proton:anti-censorship", "fastest"),
    ("proton:fastest-country", "fastest"),
    ("proton:fastest-excluding-my-country", "fastest"),
    ("proton:gaming", "fastest"),
    ("proton:max-security", "secure-core"),
    ("proton:random-country", "random"),
    ("proton:streaming-us", "fastest-in-country"),
    ("proton:work-school", "fastest"),
    ("protonwire:fastest-africa", "fastest-in-region"),
    ("protonwire:fastest-asia", "fastest-in-region"),
    ("protonwire:fastest-europe", "fastest-in-region"),
    ("protonwire:fastest-north-america", "fastest-in-region"),
    ("protonwire:fastest-oceania", "fastest-in-region"),
    ("protonwire:fastest-south-america", "fastest-in-region"),
];

/// Per-canonical-group `target.exclude_physical_country` pin: the v1
/// catalog sets the flag on exactly two groups
/// (docs/connection-groups.yaml) — deleting it there (or adding it
/// elsewhere) must be a deliberate contract change, not silent drift.
const EXPECTED_EXCLUDE_PHYSICAL_COUNTRY: [(&str, bool); 2] = [
    ("proton:anti-censorship", true),
    ("proton:fastest-excluding-my-country", true),
];

/// Per-canonical-group `target.connection_type` pin: `standard` on every
/// official group except proton:max-security, whose secure-core target
/// defines none.
const EXPECTED_CONNECTION_TYPES: [(&str, &str); 7] = [
    ("proton:anti-censorship", "standard"),
    ("proton:fastest-country", "standard"),
    ("proton:fastest-excluding-my-country", "standard"),
    ("proton:gaming", "standard"),
    ("proton:random-country", "standard"),
    ("proton:streaming-us", "standard"),
    ("proton:work-school", "standard"),
];

/// Per-canonical-group `target.selection_authority` pin: only
/// proton:random-country delegates the choice to the backend
/// ("unless backend policy controls the choice", contract.
/// ranking_policies.random-country-then-server).
const EXPECTED_SELECTION_AUTHORITIES: [(&str, &str); 1] =
    [("proton:random-country", "proton-backend-when-required")];

#[derive(Deserialize)]
pub(crate) struct GroupsFile {
    schema_version: Option<i64>,
    catalog_revision: Option<String>,
    contract: Option<Contract>,
    physical_country: Option<PhysicalCountry>,
    sources: Option<BTreeMap<String, serde_json::Value>>,
    pub(crate) regional_taxonomy: Option<RegionalTaxonomy>,
    groups: Option<Vec<Group>>,
}

#[derive(Deserialize)]
pub(crate) struct Contract {
    authoritative_owner: Option<String>,
    required_client_surfaces: Option<Vec<String>>,
    listing_network_requests: Option<String>,
    immutable_built_ins: Option<bool>,
    allowed_ranking_signals: Option<Vec<String>>,
    forbidden_ranking_signals: Option<Vec<String>>,
    ranking_policies: Option<BTreeMap<String, serde_json::Value>>,
    official_group_ranking_overrides: Option<String>,
    regional_group_ranking_overrides: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub(crate) struct PhysicalCountry {
    on_demand_request_minimum_interval_hours: Option<i64>,
    periodic_polling: Option<String>,
    forbidden_sources: Option<Vec<String>>,
    missing_policy: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RegionalTaxonomy {
    id: Option<String>,
    pub(crate) vendored_snapshot: Option<VendoredSnapshot>,
    pub(crate) primary_regions: Option<BTreeMap<String, PrimaryRegion>>,
}

#[derive(Deserialize)]
pub(crate) struct VendoredSnapshot {
    pub(crate) required_path: Option<String>,
    pub(crate) source_date: Option<String>,
    pub(crate) sha256: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct PrimaryRegion {
    pub(crate) m49_codes: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Group {
    id: Option<String>,
    definition_source: Option<String>,
    immutable: Option<bool>,
    ranking_policy: Option<String>,
    allowed_ranking_overrides: Option<Vec<String>>,
    overrides: Option<BTreeMap<String, serde_json::Value>>,
    sources: Option<Vec<String>>,
    target: Option<Target>,
}

/// A group's selection target. Every field of the v1 catalog's target
/// vocabulary is deserialized (FU-2): kind+region alone let `country`,
/// `exclude_physical_country`, the secure-core entry/exit pair,
/// `connection_type`, and `selection_authority` be silently dropped from
/// the document without failing the gate.
#[derive(Deserialize)]
struct Target {
    kind: Option<String>,
    region: Option<String>,
    country: Option<String>,
    exclude_physical_country: Option<bool>,
    entry_country: Option<String>,
    exit_country: Option<String>,
    connection_type: Option<String>,
    selection_authority: Option<String>,
}

pub fn run(root: &Path) -> Result<bool> {
    validate(&root.join("docs").join("connection-groups.yaml"))
}

pub(crate) fn load(path: &Path) -> Result<GroupsFile> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_norway::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

fn validate(path: &Path) -> Result<bool> {
    let doc = load(path)?;
    let mut reporter = Reporter::new("groups-validate");
    reporter.rule("schema_version == 1", &check_schema_version(&doc));
    reporter.rule("catalog_revision present", &check_catalog_revision(&doc));
    reporter.rule("contract", &check_contract(&doc));
    reporter.rule("physical_country", &check_physical_country(&doc));
    reporter.rule("regional_taxonomy", &check_taxonomy(&doc));
    reporter.rule("groups", &check_groups(&doc));

    let total = doc.groups.as_ref().map_or(0, Vec::len);
    let per_namespace = namespace_counts(&doc)
        .iter()
        .map(|(namespace, count)| format!("{namespace}:{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    let summary = format!("{total} group(s) ({per_namespace})");
    Ok(reporter.finish(&summary))
}

fn check_schema_version(doc: &GroupsFile) -> Vec<String> {
    match doc.schema_version {
        Some(1) => Vec::new(),
        Some(other) => vec![format!("schema_version must be 1, got {other}")],
        None => vec!["schema_version is missing".to_string()],
    }
}

fn check_catalog_revision(doc: &GroupsFile) -> Vec<String> {
    match doc.catalog_revision.as_deref().map(str::trim) {
        Some(revision) if !revision.is_empty() => Vec::new(),
        _ => vec!["catalog_revision must be a non-empty string".to_string()],
    }
}

/// Set equality against an expected vocabulary (order-insensitive).
fn expect_set(actual: Option<&[String]>, expected: &[&str], what: &str) -> Vec<String> {
    let Some(list) = actual else {
        return vec![format!("{what} is missing")];
    };
    let actual_set: BTreeSet<&str> = list.iter().map(String::as_str).collect();
    let expected_set: BTreeSet<&str> = expected.iter().copied().collect();
    if actual_set == expected_set {
        Vec::new()
    } else {
        vec![format!(
            "{what} must be exactly {expected:?} (as a set), got {list:?}"
        )]
    }
}

fn check_contract(doc: &GroupsFile) -> Vec<String> {
    let mut violations = Vec::new();
    let Some(contract) = &doc.contract else {
        return vec!["contract is missing".to_string()];
    };

    violations.extend(expect_value(
        contract.authoritative_owner.as_deref(),
        "protonwire-core",
        "contract.authoritative_owner",
    ));
    violations.extend(expect_value(
        contract.listing_network_requests.as_deref(),
        "forbidden",
        "contract.listing_network_requests",
    ));
    violations.extend(expect_value(
        contract.official_group_ranking_overrides.as_deref(),
        "forbidden",
        "contract.official_group_ranking_overrides",
    ));
    match contract.immutable_built_ins {
        Some(true) => {}
        Some(false) => violations.push("contract.immutable_built_ins must be true".to_string()),
        None => violations.push("contract.immutable_built_ins is missing".to_string()),
    }
    match contract.required_client_surfaces.as_deref() {
        Some(surfaces) if surfaces.len() == REQUIRED_CLIENT_SURFACES.len() => {
            if !surfaces
                .iter()
                .map(String::as_str)
                .eq(REQUIRED_CLIENT_SURFACES.iter().copied())
            {
                violations.push(format!(
                    "contract.required_client_surfaces must be {:?}, got {surfaces:?}",
                    REQUIRED_CLIENT_SURFACES
                ));
            }
        }
        Some(surfaces) => violations.push(format!(
            "contract.required_client_surfaces must be {:?}, got {surfaces:?}",
            REQUIRED_CLIENT_SURFACES
        )),
        None => violations.push("contract.required_client_surfaces is missing".to_string()),
    }

    violations.extend(expect_set(
        contract.allowed_ranking_signals.as_deref(),
        ALLOWED_RANKING_SIGNALS,
        "contract.allowed_ranking_signals",
    ));

    match contract.forbidden_ranking_signals.as_deref() {
        Some(signals) => {
            for signal in REQUIRED_FORBIDDEN_SIGNALS {
                if !signals.iter().any(|s| s == signal) {
                    violations.push(format!(
                        "contract.forbidden_ranking_signals must contain `{signal}`"
                    ));
                }
            }
        }
        None => violations.push("contract.forbidden_ranking_signals is missing".to_string()),
    }

    match &contract.ranking_policies {
        Some(policies) => {
            for policy in REQUIRED_RANKING_POLICIES {
                if !policies.contains_key(*policy) {
                    violations.push(format!("contract.ranking_policies is missing `{policy}`"));
                }
            }
        }
        None => violations.push("contract.ranking_policies is missing".to_string()),
    }

    violations.extend(expect_set(
        contract.regional_group_ranking_overrides.as_deref(),
        REGIONAL_RANKING_OVERRIDES,
        "contract.regional_group_ranking_overrides",
    ));

    violations
}

fn check_physical_country(doc: &GroupsFile) -> Vec<String> {
    let mut violations = Vec::new();
    let Some(physical_country) = &doc.physical_country else {
        return vec!["physical_country is missing".to_string()];
    };

    match physical_country.on_demand_request_minimum_interval_hours {
        Some(3) => {}
        Some(hours) => violations.push(format!(
            "physical_country.on_demand_request_minimum_interval_hours must be 3, got {hours}"
        )),
        None => violations.push(
            "physical_country.on_demand_request_minimum_interval_hours is missing".to_string(),
        ),
    }

    violations.extend(expect_value(
        physical_country.periodic_polling.as_deref(),
        "forbidden",
        "physical_country.periodic_polling",
    ));
    violations.extend(expect_value(
        physical_country.missing_policy.as_deref(),
        "physical-country-required",
        "physical_country.missing_policy",
    ));

    match physical_country.forbidden_sources.as_deref() {
        Some(sources) if !sources.is_empty() => {
            if !sources.iter().any(|s| s == "vpn-exit") {
                violations
                    .push("physical_country.forbidden_sources must contain `vpn-exit`".to_string());
            }
        }
        Some(_) => {
            violations.push("physical_country.forbidden_sources must not be empty".to_string())
        }
        None => violations.push("physical_country.forbidden_sources is missing".to_string()),
    }

    violations
}

fn check_taxonomy(doc: &GroupsFile) -> Vec<String> {
    let mut violations = Vec::new();
    let Some(taxonomy) = &doc.regional_taxonomy else {
        return vec!["regional_taxonomy is missing".to_string()];
    };

    violations.extend(expect_value(
        taxonomy.id.as_deref(),
        "un-m49-six-continent-view",
        "regional_taxonomy.id",
    ));
    match taxonomy.vendored_snapshot.as_ref().map(|s| s.required_path.as_deref()) {
        Some(Some("resources/geo/un-m49.csv")) => {}
        Some(Some(other)) => violations.push(format!(
            "regional_taxonomy.vendored_snapshot.required_path must be `resources/geo/un-m49.csv`, got `{other}`"
        )),
        _ => violations.push(
            "regional_taxonomy.vendored_snapshot.required_path must be `resources/geo/un-m49.csv`"
                .to_string(),
        ),
    }

    let Some(regions) = &taxonomy.primary_regions else {
        violations.push("regional_taxonomy.primary_regions is missing".to_string());
        return violations;
    };

    let expected_names: Vec<&str> = EXPECTED_REGIONS.iter().map(|(name, _)| *name).collect();
    // Compare as sorted sets: map deserialization does not guarantee the
    // document's key order.
    let mut actual_names: Vec<&str> = regions.keys().map(String::as_str).collect();
    actual_names.sort_unstable();
    let mut sorted_expected = expected_names.clone();
    sorted_expected.sort_unstable();
    if actual_names != sorted_expected {
        violations.push(format!(
            "regional_taxonomy.primary_regions must be exactly {expected_names:?}, got {actual_names:?}"
        ));
    }
    for (name, codes) in EXPECTED_REGIONS {
        match regions
            .get(*name)
            .and_then(|region| region.m49_codes.as_deref())
        {
            Some(actual) => {
                let actual_set: BTreeSet<&str> = actual.iter().map(String::as_str).collect();
                let expected_set: BTreeSet<&str> = codes.iter().copied().collect();
                if actual_set != expected_set {
                    violations.push(format!(
                        "regional_taxonomy.primary_regions.{name}.m49_codes must be {codes:?}, got {actual:?}"
                    ));
                }
            }
            None => violations.push(format!(
                "regional_taxonomy.primary_regions.{name}.m49_codes is missing"
            )),
        }
    }

    violations
}

fn check_groups(doc: &GroupsFile) -> Vec<String> {
    let mut violations = Vec::new();
    let Some(groups) = &doc.groups else {
        return vec!["groups is missing".to_string()];
    };
    if groups.len() != EXPECTED_GROUP_COUNT {
        violations.push(format!(
            "groups must contain exactly {EXPECTED_GROUP_COUNT} entries, got {}",
            groups.len()
        ));
    }

    // Compare as sorted sets, mirroring the primary_regions pin: a renamed
    // id (or an add-one-drop-one edit) must violate even at the right count.
    let mut actual_ids: Vec<&str> = groups.iter().filter_map(|g| g.id.as_deref()).collect();
    actual_ids.sort_unstable();
    let mut expected_ids = EXPECTED_GROUP_IDS;
    expected_ids.sort_unstable();
    if actual_ids != expected_ids {
        violations.push(format!(
            "group ids must be exactly {EXPECTED_GROUP_IDS:?} (as a set), got {actual_ids:?}"
        ));
    }

    let policies: BTreeSet<&str> = doc
        .contract
        .as_ref()
        .and_then(|contract| contract.ranking_policies.as_ref())
        .map(|policies| policies.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let sources: BTreeSet<&str> = doc
        .sources
        .as_ref()
        .map(|sources| sources.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let regions: BTreeSet<&str> = doc
        .regional_taxonomy
        .as_ref()
        .and_then(|taxonomy| taxonomy.primary_regions.as_ref())
        .map(|regions| regions.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let regional_overrides: BTreeSet<String> = doc
        .contract
        .as_ref()
        .and_then(|contract| contract.regional_group_ranking_overrides.as_ref())
        .map(|list| list.iter().cloned().collect())
        .unwrap_or_default();

    let mut seen = BTreeSet::new();
    for (index, group) in groups.iter().enumerate() {
        violations.extend(check_group(
            index,
            group,
            &policies,
            &sources,
            &regions,
            &regional_overrides,
            &mut seen,
        ));
    }
    violations
}

fn check_group(
    index: usize,
    group: &Group,
    policies: &BTreeSet<&str>,
    sources: &BTreeSet<&str>,
    regions: &BTreeSet<&str>,
    regional_overrides: &BTreeSet<String>,
    seen: &mut BTreeSet<String>,
) -> Vec<String> {
    let mut violations = Vec::new();
    let label = group
        .id
        .clone()
        .unwrap_or_else(|| format!("group #{index}"));

    let Some(id) = &group.id else {
        return vec![format!("{label}: `id` is missing")];
    };
    if !seen.insert(id.clone()) {
        violations.push(format!("{label}: duplicate group id"));
    }

    let namespace = id
        .strip_prefix("proton:")
        .map(|_| "proton")
        .or_else(|| id.strip_prefix("protonwire:").map(|_| "protonwire"));
    let Some(namespace) = namespace else {
        violations.push(format!(
            "{label}: id must start with `proton:` or `protonwire:`"
        ));
        return violations;
    };

    match group.definition_source.as_deref() {
        Some(source) if ALLOWED_DEFINITION_SOURCES.contains(&source) => {}
        Some(source) => violations.push(format!(
            "{label}: definition_source `{source}` is not one of {ALLOWED_DEFINITION_SOURCES:?}"
        )),
        None => violations.push(format!("{label}: `definition_source` is missing")),
    }

    if group.immutable != Some(true) {
        violations.push(format!(
            "{label}: built-in groups must have immutable == true"
        ));
    }

    match group.ranking_policy.as_deref() {
        Some(policy) if policies.contains(policy) => {}
        Some(policy) => violations.push(format!(
            "{label}: ranking_policy `{policy}` is not defined in contract.ranking_policies"
        )),
        None => violations.push(format!("{label}: `ranking_policy` is missing")),
    }

    match &group.sources {
        Some(list) => {
            for source in list {
                if !sources.contains(source.as_str()) {
                    violations.push(format!(
                        "{label}: source `{source}` is not a top-level source key"
                    ));
                }
            }
        }
        None => violations.push(format!("{label}: `sources` is missing")),
    }

    if namespace == "proton" {
        if group.allowed_ranking_overrides.is_some() {
            violations.push(format!(
                "{label}: official groups must not define allowed_ranking_overrides (official ranking overrides are forbidden)"
            ));
        }
    } else if let Some(allowed) = &group.allowed_ranking_overrides {
        for signal in allowed {
            if !regional_overrides.contains(signal) {
                violations.push(format!(
                    "{label}: allowed_ranking_overrides entry `{signal}` is not permitted by contract.regional_group_ranking_overrides"
                ));
            }
        }
    }

    violations.extend(check_target(&label, group, regions));

    if let Some(overrides) = &group.overrides {
        for key in overrides.keys() {
            if !ALLOWED_OVERRIDE_KEYS.contains(&key.as_str()) {
                violations.push(format!(
                    "{label}: overrides key `{key}` is not an allowed override key"
                ));
            }
        }
    }

    violations
}

/// Target validation: every group MUST have a target, its `kind` must be
/// in the vocabulary, the semantic fields each kind requires must be
/// present (`fastest-in-country` names a country; `secure-core` names
/// its entry and exit), `fastest-in-region` must name a primary region,
/// and each canonical id's kind is pinned (a group that resolves
/// nothing, or resolves it by unspecified means, is not a valid catalog
/// entry). The remaining semantic fields (`exclude_physical_country`,
/// `connection_type`, `selection_authority`) are pinned per canonical id
/// where the catalog defines them.
fn check_target(label: &str, group: &Group, regions: &BTreeSet<&str>) -> Vec<String> {
    let Some(target) = &group.target else {
        return vec![format!("{label}: `target` is missing")];
    };
    let mut violations = Vec::new();
    match target.kind.as_deref() {
        Some(kind) if ALLOWED_TARGET_KINDS.contains(&kind) => {
            // FU-2: per-kind semantic requirements — the fields that give
            // a kind its meaning must be present, or the target silently
            // resolves something other than its kind claims.
            match kind {
                "fastest-in-country" => {
                    if target.country.is_none() {
                        violations.push(format!(
                            "{label}: fastest-in-country targets must define target.country"
                        ));
                    }
                }
                "secure-core" => {
                    if target.entry_country.is_none() {
                        violations.push(format!(
                            "{label}: secure-core targets must define target.entry_country"
                        ));
                    }
                    if target.exit_country.is_none() {
                        violations.push(format!(
                            "{label}: secure-core targets must define target.exit_country"
                        ));
                    }
                }
                _ => {}
            }
        }
        Some(kind) => violations.push(format!(
            "{label}: target.kind `{kind}` is not one of {ALLOWED_TARGET_KINDS:?}"
        )),
        None => violations.push(format!("{label}: `target.kind` is missing")),
    }
    if target.kind.as_deref() == Some("fastest-in-region") {
        match target.region.as_deref() {
            Some(region) if regions.contains(region) => {}
            Some(region) => violations.push(format!(
                "{label}: target.region `{region}` is not a primary region"
            )),
            None => violations.push(format!(
                "{label}: fastest-in-region targets must define target.region"
            )),
        }
    }
    if let Some((_, expected)) = EXPECTED_GROUP_TARGET_KINDS
        .iter()
        .find(|(id, _)| Some(*id) == group.id.as_deref())
        && target.kind.as_deref().is_some_and(|kind| kind != *expected)
    {
        violations.push(format!("{label}: target.kind must be `{expected}`"));
    }
    violations.extend(expect_pinned(
        label,
        group.id.as_deref(),
        &EXPECTED_EXCLUDE_PHYSICAL_COUNTRY,
        target.exclude_physical_country,
        "exclude_physical_country",
    ));
    violations.extend(expect_pinned(
        label,
        group.id.as_deref(),
        &EXPECTED_CONNECTION_TYPES,
        target.connection_type.as_deref(),
        "connection_type",
    ));
    violations.extend(expect_pinned(
        label,
        group.id.as_deref(),
        &EXPECTED_SELECTION_AUTHORITIES,
        target.selection_authority.as_deref(),
        "selection_authority",
    ));
    violations
}

/// Enforces one per-canonical-id target-field pin (the
/// [`EXPECTED_GROUP_TARGET_KINDS`] style, applied to the remaining
/// semantic fields): where the v1 catalog defines the field on an id, a
/// document whose value differs — or which drops it — is silent semantic
/// drift, not a valid catalog. Ids without a pin are unconstrained.
fn expect_pinned<T: PartialEq + std::fmt::Display>(
    label: &str,
    id: Option<&str>,
    pins: &[(&str, T)],
    actual: Option<T>,
    field: &str,
) -> Vec<String> {
    let Some((_, expected)) = pins.iter().find(|(pinned, _)| Some(*pinned) == id) else {
        return Vec::new();
    };
    if actual.as_ref() == Some(expected) {
        Vec::new()
    } else {
        vec![format!("{label}: target.{field} must be `{expected}`")]
    }
}

fn namespace_counts(doc: &GroupsFile) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    if let Some(groups) = &doc.groups {
        for group in groups {
            if let Some(id) = &group.id {
                let namespace = id.split(':').next().unwrap_or("?");
                *counts.entry(namespace.to_string()).or_insert(0) += 1;
            }
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_groups_yaml() -> String {
        let mut yaml = "\
schema_version: 1
catalog_revision: \"2026-01-01\"
contract:
  authoritative_owner: protonwire-core
  required_client_surfaces: [cli, tui, gui]
  listing_network_requests: forbidden
  immutable_built_ins: true
  allowed_ranking_signals: [proton-score, load, measured-latency, stability, feature-match, history]
  forbidden_ranking_signals: [estimated-speed, estimated-throughput]
  ranking_policies:
    proton-score: official score
    balanced: weighted mix
    load: lowest load
    latency: lowest latency
    random-country-then-server: uniform
  official_group_ranking_overrides: forbidden
  regional_group_ranking_overrides: [proton-score, balanced, load, latency]
physical_country:
  on_demand_request_minimum_interval_hours: 3
  periodic_polling: forbidden
  forbidden_sources: [vpn-exit, locale]
  missing_policy: physical-country-required
sources:
  un_m49:
    url: https://unstats.un.org/unsd/methodology/m49/
  docs:
    url: https://example.com
regional_taxonomy:
  id: un-m49-six-continent-view
  vendored_snapshot:
    required_path: resources/geo/un-m49.csv
    source_date: \"2026-01-01\"
    sha256: \"0000000000000000000000000000000000000000000000000000000000000000\"
  primary_regions:
    africa: {m49_codes: [\"002\"]}
    asia: {m49_codes: [\"142\"]}
    europe: {m49_codes: [\"150\"]}
    north-america: {m49_codes: [\"021\", \"013\", \"029\"]}
    south-america: {m49_codes: [\"005\"]}
    oceania: {m49_codes: [\"009\"]}
groups:
"
        .to_string();
        // The proton targets mirror docs/connection-groups.yaml exactly:
        // connection_type, selection_authority, exclude_physical_country,
        // country, and the secure-core entry/exit pair are each entry's
        // pinned selection semantics, not decoration.
        for (id, target) in [
            (
                "proton:fastest-country",
                "{kind: fastest, connection_type: standard}",
            ),
            (
                "proton:fastest-excluding-my-country",
                "{kind: fastest, connection_type: standard, exclude_physical_country: true}",
            ),
            (
                "proton:random-country",
                "{kind: random, connection_type: standard, selection_authority: proton-backend-when-required}",
            ),
            (
                "proton:streaming-us",
                "{kind: fastest-in-country, connection_type: standard, country: US}",
            ),
            (
                "proton:gaming",
                "{kind: fastest, connection_type: standard}",
            ),
            (
                "proton:anti-censorship",
                "{kind: fastest, connection_type: standard, exclude_physical_country: true}",
            ),
            (
                "proton:max-security",
                "{kind: secure-core, entry_country: fastest, exit_country: fastest}",
            ),
            (
                "proton:work-school",
                "{kind: fastest, connection_type: standard}",
            ),
        ] {
            yaml.push_str(&format!(
                "  - id: \"{id}\"\n    definition_source: official-client-compat\n    immutable: true\n    ranking_policy: proton-score\n    overrides: {{}}\n    sources: [docs]\n    target: {target}\n"
            ));
        }
        for region in [
            "africa",
            "asia",
            "europe",
            "north-america",
            "south-america",
            "oceania",
        ] {
            yaml.push_str(&format!(
                "  - id: \"protonwire:fastest-{region}\"\n    definition_source: protonwire\n    immutable: true\n    ranking_policy: proton-score\n    allowed_ranking_overrides: [balanced, load, latency]\n    overrides: {{}}\n    sources: [un_m49]\n    target: {{kind: fastest-in-region, region: {region}}}\n"
            ));
        }
        yaml
    }

    fn temp_yaml(tag: &str, content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("xtask-groups-{tag}-{}", std::process::id()));
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn good_catalog_passes() {
        let path = temp_yaml("good", &good_groups_yaml());
        assert!(
            validate(&path).unwrap(),
            "expected the good fixture to pass"
        );
        fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_schema_version_fails() {
        let yaml = good_groups_yaml().replacen("schema_version: 1", "schema_version: 2", 1);
        let path = temp_yaml("version", &yaml);
        assert!(!validate(&path).unwrap());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn official_group_with_ranking_overrides_fails() {
        let yaml = good_groups_yaml().replacen(
            "    ranking_policy: proton-score\n    overrides: {}",
            "    ranking_policy: proton-score\n    allowed_ranking_overrides: [load]\n    overrides: {}",
            1,
        );
        let path = temp_yaml("official-override", &yaml);
        assert!(!validate(&path).unwrap());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn protonwire_group_with_out_of_contract_override_fails() {
        let yaml = good_groups_yaml().replacen(
            "allowed_ranking_overrides: [balanced, load, latency]",
            "allowed_ranking_overrides: [random-country-then-server]",
            1,
        );
        let path = temp_yaml("regional-override", &yaml);
        assert!(!validate(&path).unwrap());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_physical_country_source_fails() {
        let yaml = good_groups_yaml().replacen(
            "forbidden_sources: [vpn-exit, locale]",
            "forbidden_sources: [locale]",
            1,
        );
        let path = temp_yaml("vpn-exit", &yaml);
        assert!(!validate(&path).unwrap());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_region_codes_fail() {
        let yaml = good_groups_yaml().replacen(
            "oceania: {m49_codes: [\"009\"]}",
            "oceania: {m49_codes: [\"010\"]}",
            1,
        );
        let path = temp_yaml("codes", &yaml);
        assert!(!validate(&path).unwrap());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn group_count_is_locked() {
        let yaml = good_groups_yaml()
            .replacen("  - id: \"protonwire:fastest-oceania\"\n    definition_source: protonwire\n    immutable: true\n    ranking_policy: proton-score\n    allowed_ranking_overrides: [balanced, load, latency]\n    overrides: {}\n    sources: [un_m49]\n    target: {kind: fastest-in-region, region: oceania}\n", "", 1);
        let path = temp_yaml("count", &yaml);
        assert!(!validate(&path).unwrap());
        fs::remove_file(&path).ok();
    }

    /// Review-fix V3: the target check only fired for kind ==
    /// `fastest-in-region`, so a group with NO target (or a target whose
    /// kind is not that one) got zero validation. Every group must have a
    /// target; this deletes it from proton:fastest-country's entry (the
    /// first proton group in the fixture).
    #[test]
    fn group_without_target_fails() {
        let yaml = good_groups_yaml().replacen(
            "\n    target: {kind: fastest, connection_type: standard}\n",
            "\n",
            1,
        );
        let path = temp_yaml("no-target", &yaml);
        assert!(
            !validate(&path).unwrap(),
            "a canonical group without a target must fail validation"
        );
        fs::remove_file(&path).ok();
    }

    /// A typo'd kind must violate the pinned target.kind vocabulary.
    #[test]
    fn typoed_target_kind_fails() {
        let yaml = good_groups_yaml().replacen(
            "target: {kind: fastest, connection_type: standard}",
            "target: {kind: fatest, connection_type: standard}",
            1,
        );
        let path = temp_yaml("typo-kind", &yaml);
        assert!(
            !validate(&path).unwrap(),
            "a target.kind outside the vocabulary must fail validation"
        );
        fs::remove_file(&path).ok();
    }

    /// `fastest-in-region` is meaningless without its region.
    #[test]
    fn fastest_in_region_without_region_fails() {
        let yaml = good_groups_yaml().replacen(
            "target: {kind: fastest-in-region, region: africa}",
            "target: {kind: fastest-in-region}",
            1,
        );
        let path = temp_yaml("no-region", &yaml);
        assert!(
            !validate(&path).unwrap(),
            "fastest-in-region without a region must fail validation"
        );
        fs::remove_file(&path).ok();
    }

    /// FU-1 (rust-review round-5 follow-up, Medium — the repo's own
    /// red-test rule): swapping a canonical id's kind for ANOTHER VALID
    /// kind stays inside the vocabulary and still resolves something, so
    /// every other check passes — only the EXPECTED_GROUP_TARGET_KINDS
    /// pin in `check_target` catches the drift. Deleting that enforcement
    /// block used to leave every test AND the CI gate green (the real
    /// document satisfies the pin, so only a mutated fixture can expose
    /// the gap). Both target lines are unique in the fixture, so each
    /// `replacen` targets exactly one group: `random` → `fastest` on
    /// proton:random-country and `secure-core` → `fastest` on
    /// proton:max-security (the non-ambiguous secure-core line); the
    /// swapped targets keep every other pinned field (connection_type,
    /// selection_authority, entry/exit) intact, so the kind pin is the
    /// only rule that fires.
    #[test]
    fn kind_swapped_for_another_valid_kind_fails() {
        for (original, swapped) in [
            (
                "target: {kind: random, connection_type: standard, selection_authority: proton-backend-when-required}",
                "target: {kind: fastest, connection_type: standard, selection_authority: proton-backend-when-required}",
            ),
            (
                "target: {kind: secure-core, entry_country: fastest, exit_country: fastest}",
                "target: {kind: fastest}",
            ),
        ] {
            let yaml = good_groups_yaml().replacen(original, swapped, 1);
            let path = temp_yaml("kind-swap", &yaml);
            assert!(
                !validate(&path).unwrap(),
                "swapping `{original}` for `{swapped}` must fail validation: a \
                 canonical id's pinned target kind must not drift"
            );
            fs::remove_file(&path).ok();
        }
    }

    /// FU-2 (rust-review round-5 follow-up, Medium): `Target` used to
    /// deserialize only kind+region, so `country` was silently dropped —
    /// deleting it from proton:streaming-us left a `fastest-in-country`
    /// target with nothing to be fastest IN, and the gate stayed green.
    #[test]
    fn fastest_in_country_without_country_fails() {
        let yaml = good_groups_yaml().replacen(
            "target: {kind: fastest-in-country, connection_type: standard, country: US}",
            "target: {kind: fastest-in-country, connection_type: standard}",
            1,
        );
        let path = temp_yaml("no-country", &yaml);
        assert!(
            !validate(&path).unwrap(),
            "fastest-in-country without target.country must fail validation"
        );
        fs::remove_file(&path).ok();
    }

    /// FU-2: same silent-drop gap for `exclude_physical_country` — the
    /// flag IS the group's meaning on the two ids the catalog sets it on.
    /// The first (and only, until anti-censorship's) occurrence of this
    /// target line is proton:fastest-excluding-my-country, the fixture's
    /// proton order.
    #[test]
    fn exclude_physical_country_deletion_fails() {
        let yaml = good_groups_yaml().replacen(
            "target: {kind: fastest, connection_type: standard, exclude_physical_country: true}",
            "target: {kind: fastest, connection_type: standard}",
            1,
        );
        let path = temp_yaml("no-exclude", &yaml);
        assert!(
            !validate(&path).unwrap(),
            "deleting target.exclude_physical_country from a pinned canonical \
             group must fail validation"
        );
        fs::remove_file(&path).ok();
    }

    /// FU-2: a secure-core target without its exit country silently
    /// selects nothing the kind names. The catalog pins both
    /// entry_country and exit_country on proton:max-security
    /// (`fastest`/`fastest`); the entry half alone must not pass.
    #[test]
    fn secure_core_without_exit_country_fails() {
        let yaml = good_groups_yaml().replacen(
            "target: {kind: secure-core, entry_country: fastest, exit_country: fastest}",
            "target: {kind: secure-core, entry_country: fastest}",
            1,
        );
        let path = temp_yaml("no-exit", &yaml);
        assert!(
            !validate(&path).unwrap(),
            "secure-core without target.exit_country must fail validation"
        );
        fs::remove_file(&path).ok();
    }

    /// The region must be one of the taxonomy's primary regions
    /// (EXPECTED_REGIONS), not an arbitrary string.
    #[test]
    fn fastest_in_region_with_unknown_region_fails() {
        let yaml = good_groups_yaml().replacen(
            "target: {kind: fastest-in-region, region: africa}",
            "target: {kind: fastest-in-region, region: atlantis}",
            1,
        );
        let path = temp_yaml("bad-region", &yaml);
        assert!(
            !validate(&path).unwrap(),
            "fastest-in-region with a region outside EXPECTED_REGIONS must fail validation"
        );
        fs::remove_file(&path).ok();
    }

    #[test]
    fn canonical_ids_have_valid_namespaces_and_are_unique() {
        // The `[&str; EXPECTED_GROUP_COUNT]` array type already pins the
        // length at compile time, so a runtime len() assert was provably
        // always-true. What the type does NOT pin: every id living in a
        // valid namespace, and uniqueness (a duplicated id at the right
        // length would still compile and silently weaken the set check).
        for id in EXPECTED_GROUP_IDS {
            assert!(
                id.starts_with("proton:") || id.starts_with("protonwire:"),
                "`{id}` must live in the `proton:` or `protonwire:` namespace"
            );
        }
        let unique: BTreeSet<&str> = EXPECTED_GROUP_IDS.iter().copied().collect();
        assert_eq!(
            unique.len(),
            EXPECTED_GROUP_COUNT,
            "the pinned id set must contain exactly {EXPECTED_GROUP_COUNT} unique ids"
        );
    }

    /// The per-group kind map pins exactly the canonical ids (no strays,
    /// no gaps) with the v1 catalog's kind distribution: 5x fastest, 1x
    /// random, 1x fastest-in-country, 1x secure-core, 6x fastest-in-region.
    #[test]
    fn canonical_target_kind_map_is_pinned() {
        let ids: BTreeSet<&str> = EXPECTED_GROUP_IDS.iter().copied().collect();
        let pinned_ids: BTreeSet<&str> = EXPECTED_GROUP_TARGET_KINDS
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(
            pinned_ids, ids,
            "the kind map must cover exactly the canonical ids"
        );
        let mut distribution: BTreeMap<&str, usize> = BTreeMap::new();
        for (_, kind) in EXPECTED_GROUP_TARGET_KINDS {
            assert!(
                ALLOWED_TARGET_KINDS.contains(&kind),
                "pinned kind `{kind}` must be in the vocabulary"
            );
            *distribution.entry(kind).or_default() += 1;
        }
        assert_eq!(distribution.get("fastest"), Some(&5));
        assert_eq!(distribution.get("random"), Some(&1));
        assert_eq!(distribution.get("fastest-in-country"), Some(&1));
        assert_eq!(distribution.get("secure-core"), Some(&1));
        assert_eq!(distribution.get("fastest-in-region"), Some(&6));
    }

    #[test]
    fn renamed_group_id_violates() {
        // The count check alone lets a renamed canonical id through; the
        // v1 catalog's id set itself must be pinned.
        let yaml =
            good_groups_yaml().replacen("proton:fastest-country", "proton:fastest-nation", 1);
        let path = temp_yaml("renamed-id", &yaml);
        assert!(
            !validate(&path).unwrap(),
            "a renamed canonical group id must fail validation"
        );
        fs::remove_file(&path).ok();
    }

    #[test]
    fn unknown_override_key_fails() {
        let yaml = good_groups_yaml().replacen(
            "  - id: \"proton:fastest-country\"\n    definition_source: official-client-compat\n    immutable: true\n    ranking_policy: proton-score\n    overrides: {}",
            "  - id: \"proton:fastest-country\"\n    definition_source: official-client-compat\n    immutable: true\n    ranking_policy: proton-score\n    overrides: {color: red}",
            1,
        );
        let path = temp_yaml("override-key", &yaml);
        assert!(!validate(&path).unwrap());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn ranking_signal_set_is_locked() {
        let doc: GroupsFile =
            serde_norway::from_str("contract:\n  allowed_ranking_signals: [proton-score, load]\n")
                .unwrap();
        assert!(!check_contract(&doc).is_empty());

        let doc: GroupsFile =
            serde_norway::from_str("physical_country:\n  forbidden_sources: [locale]\n").unwrap();
        assert!(
            check_physical_country(&doc)
                .iter()
                .any(|v| v.contains("vpn-exit"))
        );
    }
}
