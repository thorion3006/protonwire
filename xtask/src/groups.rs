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

#[derive(Deserialize)]
struct Target {
    kind: Option<String>,
    region: Option<String>,
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

    if let Some(target) = &group.target
        && target.kind.as_deref() == Some("fastest-in-region")
    {
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
        for i in 0..8 {
            yaml.push_str(&format!(
                "  - id: \"proton:g{i}\"\n    definition_source: official-client-compat\n    immutable: true\n    ranking_policy: proton-score\n    overrides: {{}}\n    sources: [docs]\n    target: {{kind: fastest}}\n"
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

    #[test]
    fn unknown_override_key_fails() {
        let yaml = good_groups_yaml().replacen(
            "  - id: \"proton:g0\"\n    definition_source: official-client-compat\n    immutable: true\n    ranking_policy: proton-score\n    overrides: {}",
            "  - id: \"proton:g0\"\n    definition_source: official-client-compat\n    immutable: true\n    ranking_policy: proton-score\n    overrides: {color: red}",
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
