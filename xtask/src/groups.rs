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

/// The exact `physical_country.forbidden_sources` set the v1 contract
/// carries (docs/connection-groups.yaml): the five sources a physical
/// country must never be inferred from.
const EXPECTED_FORBIDDEN_SOURCES: &[&str] = &[
    "vpn-exit",
    "account-country",
    "locale",
    "timezone",
    "third-party-geolocation",
];

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

/// The golden canonical groups table (round-9 structural disposal): one
/// FULLY-RENDERED definition per built-in group, keyed by id, generated
/// from docs/connection-groups.yaml itself — the document IS the golden
/// source; this constant records its rendering so the gate compares the
/// validated document against the canonical table rather than against
/// hand-transcribed per-field expectations. It replaces the retired
/// field-by-field pin family (per-id target kinds, exclude flags,
/// connection types, selection authorities, override maps), which had
/// admitted one-more-unpinned-field three review rounds running: the
/// rendering is produced from the RAW entry, so every field — including
/// ones no typed struct deserializes, and fields added to the document
/// after this constant was recorded — participates in the comparison.
/// A deliberate contract change regenerates this constant from the
/// edited document (see the test-only crosscheck against the real yaml).
const GOLDEN_GROUP_ENTRIES: &[(&str, &str)] = &[
    (
        "proton:fastest-country",
        r#"definition_source: official-client-compat
entitlement: plan-dependent
id: proton:fastest-country
immutable: true
label: Fastest country
origin: proton
overrides: {}
ranking_policy: proton-score
sources:
- proton_default_connection
- proton_connection_profiles
target:
  connection_type: standard
  kind: fastest
"#,
    ),
    (
        "proton:fastest-excluding-my-country",
        r#"definition_source: official-client-compat
entitlement: plan-dependent
id: proton:fastest-excluding-my-country
immutable: true
label: Fastest country (excluding my country)
origin: proton
overrides: {}
ranking_policy: proton-score
sources:
- android_fastest_exclusion
- proton_windows_release_notes
target:
  connection_type: standard
  exclude_physical_country: true
  kind: fastest
"#,
    ),
    (
        "proton:random-country",
        r#"definition_source: official-client-compat
entitlement: plan-dependent
id: proton:random-country
immutable: true
label: Random country
origin: proton
overrides: {}
ranking_policy: random-country-then-server
sources:
- proton_default_connection
- proton_windows_release_notes
target:
  connection_type: standard
  kind: random
  selection_authority: proton-backend-when-required
"#,
    ),
    (
        "proton:streaming-us",
        r#"definition_source: official-client-compat
entitlement: target-and-feature-dependent
id: proton:streaming-us
immutable: true
label: Streaming US
origin: proton
overrides:
  protocol: wireguard-udp
ranking_policy: proton-score
sources:
- android_initial_profiles
target:
  connection_type: standard
  country: US
  kind: fastest-in-country
"#,
    ),
    (
        "proton:gaming",
        r#"definition_source: official-client-compat
entitlement: target-and-feature-dependent
id: proton:gaming
immutable: true
label: Gaming
origin: proton
overrides:
  nat: moderate
ranking_policy: proton-score
sources:
- android_initial_profiles
target:
  connection_type: standard
  kind: fastest
"#,
    ),
    (
        "proton:anti-censorship",
        r#"definition_source: official-client-compat
entitlement: target-and-feature-dependent
id: proton:anti-censorship
immutable: true
label: Anti-censorship
origin: proton
overrides:
  protocol: stealth
ranking_policy: proton-score
sources:
- android_initial_profiles
- android_fastest_exclusion
target:
  connection_type: standard
  exclude_physical_country: true
  kind: fastest
"#,
    ),
    (
        "proton:max-security",
        r#"definition_source: official-client-compat
entitlement: target-and-feature-dependent
id: proton:max-security
immutable: true
label: Max security
origin: proton
overrides:
  lan_access: block
ranking_policy: proton-score
sources:
- android_initial_profiles
target:
  entry_country: fastest
  exit_country: fastest
  kind: secure-core
"#,
    ),
    (
        "proton:work-school",
        r#"definition_source: official-client-compat
entitlement: target-and-feature-dependent
id: proton:work-school
immutable: true
label: Work/School
origin: proton
overrides:
  lan_access: block
  protocol: stealth
ranking_policy: proton-score
sources:
- android_initial_profiles
target:
  connection_type: standard
  kind: fastest
"#,
    ),
    (
        "protonwire:fastest-africa",
        r#"allowed_ranking_overrides:
- balanced
- load
- latency
definition_source: protonwire
entitlement: paid-location-selection
id: protonwire:fastest-africa
immutable: true
label: Fastest Africa
origin: protonwire
overrides: {}
ranking_policy: proton-score
sources:
- un_m49
target:
  kind: fastest-in-region
  region: africa
"#,
    ),
    (
        "protonwire:fastest-asia",
        r#"allowed_ranking_overrides:
- balanced
- load
- latency
definition_source: protonwire
entitlement: paid-location-selection
id: protonwire:fastest-asia
immutable: true
label: Fastest Asia
origin: protonwire
overrides: {}
ranking_policy: proton-score
sources:
- un_m49
target:
  kind: fastest-in-region
  region: asia
"#,
    ),
    (
        "protonwire:fastest-europe",
        r#"allowed_ranking_overrides:
- balanced
- load
- latency
definition_source: protonwire
entitlement: paid-location-selection
id: protonwire:fastest-europe
immutable: true
label: Fastest Europe
origin: protonwire
overrides: {}
ranking_policy: proton-score
sources:
- un_m49
target:
  kind: fastest-in-region
  region: europe
"#,
    ),
    (
        "protonwire:fastest-north-america",
        r#"allowed_ranking_overrides:
- balanced
- load
- latency
definition_source: protonwire
entitlement: paid-location-selection
id: protonwire:fastest-north-america
immutable: true
label: Fastest North America
origin: protonwire
overrides: {}
ranking_policy: proton-score
sources:
- un_m49
target:
  kind: fastest-in-region
  region: north-america
"#,
    ),
    (
        "protonwire:fastest-south-america",
        r#"allowed_ranking_overrides:
- balanced
- load
- latency
definition_source: protonwire
entitlement: paid-location-selection
id: protonwire:fastest-south-america
immutable: true
label: Fastest South America
origin: protonwire
overrides: {}
ranking_policy: proton-score
sources:
- un_m49
target:
  kind: fastest-in-region
  region: south-america
"#,
    ),
    (
        "protonwire:fastest-oceania",
        r#"allowed_ranking_overrides:
- balanced
- load
- latency
definition_source: protonwire
entitlement: paid-location-selection
id: protonwire:fastest-oceania
immutable: true
label: Fastest Oceania
origin: protonwire
overrides: {}
ranking_policy: proton-score
sources:
- un_m49
target:
  kind: fastest-in-region
  region: oceania
"#,
    ),
];

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

/// A group's selection target, carrying exactly the fields the STRUCTURAL
/// rules consult: `kind` (vocabulary + per-kind semantics), `region`
/// (primary-region membership), `country`, and the secure-core entry/exit
/// pair (per-kind required fields, FU-2). The remaining target fields
/// (`exclude_physical_country`, `connection_type`,
/// `selection_authority`) used to be deserialized for the retired
/// per-id value pins; their drift coverage moved to the golden-table
/// rule, which compares the RAW entry — every target field, including
/// ones this struct never names — against the golden rendering.
#[derive(Deserialize)]
struct Target {
    kind: Option<String>,
    region: Option<String>,
    country: Option<String>,
    entry_country: Option<String>,
    exit_country: Option<String>,
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
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let doc: GroupsFile = serde_norway::from_str(&text)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    // The golden-table rule compares RAW entries (every field the document
    // carries, not only the fields the typed structs deserialize), so the
    // text is parsed a second time into an untyped value.
    let raw: serde_json::Value = serde_norway::from_str(&text)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let mut reporter = Reporter::new("groups-validate");
    reporter.rule("schema_version == 1", &check_schema_version(&doc));
    reporter.rule("catalog_revision present", &check_catalog_revision(&doc));
    reporter.rule("contract", &check_contract(&doc));
    reporter.rule("physical_country", &check_physical_country(&doc));
    reporter.rule("regional_taxonomy", &check_taxonomy(&doc));
    reporter.rule(
        "canonical groups table (golden document equality)",
        &check_golden_groups_table(&raw),
    );
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

    // Round-8 X8: partial retention of the forbidden set passed — the
    // old check required only `vpn-exit`. The exact five-source set is
    // pinned: every missing source and every extra one is a named
    // violation (an empty list is the all-missing case).
    match physical_country.forbidden_sources.as_deref() {
        Some(sources) => {
            let actual: BTreeSet<&str> = sources.iter().map(String::as_str).collect();
            let expected: BTreeSet<&str> = EXPECTED_FORBIDDEN_SOURCES.iter().copied().collect();
            for source in expected.difference(&actual) {
                violations.push(format!(
                    "physical_country.forbidden_sources must contain `{source}`"
                ));
            }
            for source in actual.difference(&expected) {
                violations.push(format!(
                    "physical_country.forbidden_sources must not contain `{source}` \
                     (not part of the canonical five-source set)"
                ));
            }
        }
        None => violations.push("physical_country.forbidden_sources is missing".to_string()),
    }

    violations
}

pub(crate) fn check_taxonomy(doc: &GroupsFile) -> Vec<String> {
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

/// Canonical rendering of one RAW `groups` entry: the entry is
/// re-serialized from its untyped JSON value, whose maps are
/// BTreeMap-backed (no `preserve_order` anywhere in the workspace), so
/// keys come out sorted and the rendering is invariant under key
/// reordering in the source yaml. Two entries render identically iff
/// they carry the same fields with the same values — the full canonical
/// definition, not a hand-picked subset of it.
fn render_group_entry(entry: &serde_json::Value) -> String {
    serde_norway::to_string(entry).expect("a JSON value always re-serializes as YAML")
}

/// The round-9 structural disposal, in force: every built-in group's
/// FULL canonical definition is compared against the golden rendering of
/// docs/connection-groups.yaml ([`GOLDEN_GROUP_ENTRIES`]). This single
/// rule subsumes the retired per-field pin family — any value flip,
/// dropped field, added field (known or unknown to the typed structs),
/// or cross-entry swap of any canonical value is drift — while the
/// structural rules it does NOT subsume (id set, namespaces, target-kind
/// vocabulary, per-kind required fields, cross-references into
/// contract/sources/taxonomy) stay in `check_groups`/`check_target`.
pub(crate) fn check_golden_groups_table(raw: &serde_json::Value) -> Vec<String> {
    let Some(entries) = raw.get("groups").and_then(serde_json::Value::as_array) else {
        // The `groups` structural rule already reports the missing list.
        return Vec::new();
    };
    let golden: BTreeMap<&str, &str> = GOLDEN_GROUP_ENTRIES.iter().copied().collect();
    let mut violations = Vec::new();
    let mut actual_ids: Vec<&str> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let id = entry
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("#<no id>");
        let rendered = render_group_entry(entry);
        actual_ids.push(id);
        match golden.get(id) {
            Some(expected) if rendered == **expected => {}
            Some(_) => violations.push(format!(
                "{id}: full canonical definition drifted from the golden groups table \
                 (docs/connection-groups.yaml is the golden source — a deliberate \
                 contract change regenerates GOLDEN_GROUP_ENTRIES)"
            )),
            None => violations.push(format!(
                "{id} (entry #{index}): group is not part of the golden canonical table"
            )),
        }
    }
    for id in golden.keys() {
        if !actual_ids.contains(id) {
            violations.push(format!(
                "{id}: canonical golden group is missing from the document"
            ));
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
/// in the vocabulary, and the semantic fields each kind requires must be
/// present (`fastest-in-country` names a country; `secure-core` names
/// its entry and exit; `fastest-in-region` names a primary region) — a
/// group that resolves nothing, or resolves it by unspecified means, is
/// not a valid catalog entry. Per-canonical-id VALUE pins used to live
/// here (kind, exclude flag, connection type, selection authority per
/// id); they are retired, subsumed by the golden-table rule, which
/// compares every entry's full definition — these fields included —
/// against the golden rendering.
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
        let yaml = "\
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
  forbidden_sources: [vpn-exit, account-country, locale, timezone, third-party-geolocation]
  missing_policy: physical-country-required
sources:
  un_m49:
    url: https://unstats.un.org/unsd/methodology/m49/
  docs:
    url: https://example.com
  proton_default_connection:
    url: https://protonvpn.com/support/default-connection
  proton_connection_profiles:
    url: https://protonvpn.com/support/connection-profiles
  proton_windows_release_notes:
    url: https://protonvpn.com/support/release-notes-windows
  android_initial_profiles:
    url: https://example.com/initial-profiles
  android_fastest_exclusion:
    url: https://example.com/fastest-exclusion
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
  - id: \"proton:fastest-country\"
    label: Fastest country
    origin: proton
    definition_source: official-client-compat
    immutable: true
    entitlement: plan-dependent
    target:
      kind: fastest
      connection_type: standard
    ranking_policy: proton-score
    overrides: {}
    sources: [proton_default_connection, proton_connection_profiles]

  - id: \"proton:fastest-excluding-my-country\"
    label: Fastest country (excluding my country)
    origin: proton
    definition_source: official-client-compat
    immutable: true
    entitlement: plan-dependent
    target:
      kind: fastest
      connection_type: standard
      exclude_physical_country: true
    ranking_policy: proton-score
    overrides: {}
    sources: [android_fastest_exclusion, proton_windows_release_notes]

  - id: \"proton:random-country\"
    label: Random country
    origin: proton
    definition_source: official-client-compat
    immutable: true
    entitlement: plan-dependent
    target:
      kind: random
      connection_type: standard
      selection_authority: proton-backend-when-required
    ranking_policy: random-country-then-server
    overrides: {}
    sources: [proton_default_connection, proton_windows_release_notes]

  - id: \"proton:streaming-us\"
    label: Streaming US
    origin: proton
    definition_source: official-client-compat
    immutable: true
    entitlement: target-and-feature-dependent
    target:
      kind: fastest-in-country
      connection_type: standard
      country: US
    ranking_policy: proton-score
    overrides:
      protocol: wireguard-udp
    sources: [android_initial_profiles]

  - id: \"proton:gaming\"
    label: Gaming
    origin: proton
    definition_source: official-client-compat
    immutable: true
    entitlement: target-and-feature-dependent
    target:
      kind: fastest
      connection_type: standard
    ranking_policy: proton-score
    overrides:
      nat: moderate
    sources: [android_initial_profiles]

  - id: \"proton:anti-censorship\"
    label: Anti-censorship
    origin: proton
    definition_source: official-client-compat
    immutable: true
    entitlement: target-and-feature-dependent
    target:
      kind: fastest
      connection_type: standard
      exclude_physical_country: true
    ranking_policy: proton-score
    overrides:
      protocol: stealth
    sources: [android_initial_profiles, android_fastest_exclusion]

  - id: \"proton:max-security\"
    label: Max security
    origin: proton
    definition_source: official-client-compat
    immutable: true
    entitlement: target-and-feature-dependent
    target:
      kind: secure-core
      entry_country: fastest
      exit_country: fastest
    ranking_policy: proton-score
    overrides:
      lan_access: block
    sources: [android_initial_profiles]

  - id: \"proton:work-school\"
    label: Work/School
    origin: proton
    definition_source: official-client-compat
    immutable: true
    entitlement: target-and-feature-dependent
    target:
      kind: fastest
      connection_type: standard
    ranking_policy: proton-score
    overrides:
      protocol: stealth
      lan_access: block
    sources: [android_initial_profiles]

  - id: \"protonwire:fastest-africa\"
    label: Fastest Africa
    origin: protonwire
    definition_source: protonwire
    immutable: true
    entitlement: paid-location-selection
    target:
      kind: fastest-in-region
      region: africa
    ranking_policy: proton-score
    allowed_ranking_overrides: [balanced, load, latency]
    overrides: {}
    sources: [un_m49]

  - id: \"protonwire:fastest-asia\"
    label: Fastest Asia
    origin: protonwire
    definition_source: protonwire
    immutable: true
    entitlement: paid-location-selection
    target:
      kind: fastest-in-region
      region: asia
    ranking_policy: proton-score
    allowed_ranking_overrides: [balanced, load, latency]
    overrides: {}
    sources: [un_m49]

  - id: \"protonwire:fastest-europe\"
    label: Fastest Europe
    origin: protonwire
    definition_source: protonwire
    immutable: true
    entitlement: paid-location-selection
    target:
      kind: fastest-in-region
      region: europe
    ranking_policy: proton-score
    allowed_ranking_overrides: [balanced, load, latency]
    overrides: {}
    sources: [un_m49]

  - id: \"protonwire:fastest-north-america\"
    label: Fastest North America
    origin: protonwire
    definition_source: protonwire
    immutable: true
    entitlement: paid-location-selection
    target:
      kind: fastest-in-region
      region: north-america
    ranking_policy: proton-score
    allowed_ranking_overrides: [balanced, load, latency]
    overrides: {}
    sources: [un_m49]

  - id: \"protonwire:fastest-south-america\"
    label: Fastest South America
    origin: protonwire
    definition_source: protonwire
    immutable: true
    entitlement: paid-location-selection
    target:
      kind: fastest-in-region
      region: south-america
    ranking_policy: proton-score
    allowed_ranking_overrides: [balanced, load, latency]
    overrides: {}
    sources: [un_m49]

  - id: \"protonwire:fastest-oceania\"
    label: Fastest Oceania
    origin: protonwire
    definition_source: protonwire
    immutable: true
    entitlement: paid-location-selection
    target:
      kind: fastest-in-region
      region: oceania
    ranking_policy: proton-score
    allowed_ranking_overrides: [balanced, load, latency]
    overrides: {}
    sources: [un_m49]
"
        .to_string();
        // The groups table mirrors docs/connection-groups.yaml verbatim:
        // it must stay byte-faithful to the canonical entries (only the
        // surrounding sections — sources, taxonomy — are fixture-local),
        // because the golden-table rule compares the fixture's table
        // against the same pinned golden rendering as the real document.
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

    /// Round-9 post-close disposal (structural): the field-by-field pin
    /// family had admitted one-more-unpinned-field three review rounds
    /// running — every per-id pin only ever covered the fields a past
    /// review noticed. The first five edits each stay inside every
    /// vocabulary and cross-reference the gate checks (a DEFINED ranking
    /// policy, a defined source key, the allowed definition-source
    /// vocabulary, a field no check deserializes), so the pre-golden
    /// gate let them all through (observed red on landing: the first
    /// case alone was enough to fail the suite pre-implementation). The
    /// remaining cases are the retired pin family's mutations (FU-1
    /// kind-swaps, the FU-2 exclude-flag deletion, round-8 X7 override
    /// drift), folded in so their drift classes stay covered now that
    /// the per-id pins are gone — every case must fail via the
    /// golden-table rule.
    #[test]
    fn canonical_group_edits_fail_the_golden_table() {
        let fastest_country_sources =
            "overrides: {}\n    sources: [proton_default_connection, proton_connection_profiles]";
        for (label, original, swapped) in [
            (
                "ranking policy swapped for another defined policy",
                "ranking_policy: proton-score\n    overrides: {}\n    sources: [proton_default_connection",
                "ranking_policy: load\n    overrides: {}\n    sources: [proton_default_connection",
            ),
            (
                "cited source dropped from the list",
                fastest_country_sources,
                "overrides: {}\n    sources: [proton_default_connection]",
            ),
            (
                "label edited",
                "label: Fastest country\n    origin: proton",
                "label: Fastest nation\n    origin: proton",
            ),
            (
                "unknown field added to the entry",
                "entitlement: plan-dependent\n    target:\n      kind: fastest\n      connection_type: standard\n    ranking_policy: proton-score",
                "entitlement: plan-dependent\n    note: scratch\n    target:\n      kind: fastest\n      connection_type: standard\n    ranking_policy: proton-score",
            ),
            (
                "definition source swapped within the vocabulary",
                "  - id: \"proton:fastest-country\"\n    label: Fastest country\n    origin: proton\n    definition_source: official-client-compat",
                "  - id: \"proton:fastest-country\"\n    label: Fastest country\n    origin: proton\n    definition_source: proton-api",
            ),
            // Retired FU-1 pin cases: kinds swapped for OTHER VALID kinds
            // stay inside the vocabulary and resolve something.
            (
                "kind swapped for another valid kind (random)",
                "target:\n      kind: random\n      connection_type: standard\n      selection_authority: proton-backend-when-required",
                "target:\n      kind: fastest\n      connection_type: standard\n      selection_authority: proton-backend-when-required",
            ),
            (
                "kind swapped for another valid kind (secure-core)",
                "target:\n      kind: secure-core\n      entry_country: fastest\n      exit_country: fastest",
                "target:\n      kind: fastest",
            ),
            // Retired FU-2 pin case: the exclude flag IS the group's
            // meaning on the two ids the catalog sets it on.
            (
                "exclude_physical_country deleted",
                "target:\n      kind: fastest\n      connection_type: standard\n      exclude_physical_country: true\n",
                "target:\n      kind: fastest\n      connection_type: standard\n",
            ),
            // Retired round-8 X7 pin cases: override VALUE drift, a pinned
            // override dropped, an override added to a pinned-empty group.
            (
                "override value flipped",
                "overrides:\n      lan_access: block\n    sources: [android_initial_profiles]\n\n  - id: \"proton:work-school\"",
                "overrides:\n      lan_access: allow\n    sources: [android_initial_profiles]\n\n  - id: \"proton:work-school\"",
            ),
            (
                "pinned override dropped",
                "overrides:\n      lan_access: block\n    sources: [android_initial_profiles]\n\n  - id: \"proton:work-school\"",
                "overrides: {}\n    sources: [android_initial_profiles]\n\n  - id: \"proton:work-school\"",
            ),
            (
                "override added to a pinned-empty group",
                "overrides: {}\n    sources: [proton_default_connection, proton_connection_profiles]",
                "overrides:\n      protocol: stealth\n    sources: [proton_default_connection, proton_connection_profiles]",
            ),
        ] {
            let yaml = good_groups_yaml().replacen(original, swapped, 1);
            let path = temp_yaml("golden-drift", &yaml);
            assert!(
                !validate(&path).unwrap(),
                "{label}: editing a canonical group's full definition must fail \
                 validation, not only the fields a past round happened to pin"
            );
            fs::remove_file(&path).ok();
        }
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
            "forbidden_sources: [vpn-exit, account-country, locale, timezone, third-party-geolocation]",
            "forbidden_sources: [account-country, locale, timezone, third-party-geolocation]",
            1,
        );
        let path = temp_yaml("vpn-exit", &yaml);
        assert!(!validate(&path).unwrap());
        fs::remove_file(&path).ok();
    }

    /// Round-8 X8: partial retention of the forbidden-source set passed —
    /// the check required only `vpn-exit`, so dropping any of the other
    /// four documented sources (or adding a sixth) was silent drift. The
    /// exact five-source set is pinned; every missing or extra source is
    /// a violation naming it.
    #[test]
    fn partial_forbidden_sources_set_fails() {
        let removed = serde_norway::from_str::<GroupsFile>(
            "physical_country:\n  forbidden_sources: [vpn-exit, account-country, locale, third-party-geolocation]\n",
        )
        .unwrap();
        let violations = check_physical_country(&removed);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("must contain `timezone`")),
            "dropping `timezone` must be a violation naming it, got {violations:?}"
        );

        let extra = serde_norway::from_str::<GroupsFile>(
            "physical_country:\n  forbidden_sources: [vpn-exit, account-country, locale, timezone, third-party-geolocation, ip-geolocation]\n",
        )
        .unwrap();
        let violations = check_physical_country(&extra);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("must not contain `ip-geolocation`")),
            "a sixth source must be a violation naming it, got {violations:?}"
        );

        let pinned: BTreeSet<&str> = EXPECTED_FORBIDDEN_SOURCES.iter().copied().collect();
        assert_eq!(
            pinned.len(),
            5,
            "the canonical forbidden-source set has exactly five members"
        );
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
        let yaml = good_groups_yaml().replacen(
            "  - id: \"protonwire:fastest-oceania\"\n    label: Fastest Oceania\n    origin: protonwire\n    definition_source: protonwire\n    immutable: true\n    entitlement: paid-location-selection\n    target:\n      kind: fastest-in-region\n      region: oceania\n    ranking_policy: proton-score\n    allowed_ranking_overrides: [balanced, load, latency]\n    overrides: {}\n    sources: [un_m49]\n",
            "",
            1,
        );
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
            "\n    target:\n      kind: fastest\n      connection_type: standard\n    ranking_policy: proton-score\n    overrides: {}\n    sources: [proton_default_connection, proton_connection_profiles]",
            "\n    ranking_policy: proton-score\n    overrides: {}\n    sources: [proton_default_connection, proton_connection_profiles]",
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
            "target:\n      kind: fastest\n      connection_type: standard\n    ranking_policy: proton-score\n    overrides: {}\n    sources: [proton_default_connection",
            "target:\n      kind: fatest\n      connection_type: standard\n    ranking_policy: proton-score\n    overrides: {}\n    sources: [proton_default_connection",
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
            "target:\n      kind: fastest-in-region\n      region: africa\n",
            "target:\n      kind: fastest-in-region\n",
            1,
        );
        let path = temp_yaml("no-region", &yaml);
        assert!(
            !validate(&path).unwrap(),
            "fastest-in-region without a region must fail validation"
        );
        fs::remove_file(&path).ok();
    }

    /// FU-2 (rust-review round-5 follow-up, Medium): `Target` used to
    /// deserialize only kind+region, so `country` was silently dropped —
    /// deleting it from proton:streaming-us left a `fastest-in-country`
    /// target with nothing to be fastest IN, and the gate stayed green.
    /// (The per-id VALUE pins this used to lean on are retired — the
    /// golden-table rule catches this edit too — but the per-kind
    /// structural requirement stays: a fastest-in-country target with no
    /// country resolves nothing its kind names.)
    #[test]
    fn fastest_in_country_without_country_fails() {
        let yaml = good_groups_yaml().replacen(
            "target:\n      kind: fastest-in-country\n      connection_type: standard\n      country: US\n",
            "target:\n      kind: fastest-in-country\n      connection_type: standard\n",
            1,
        );
        let path = temp_yaml("no-country", &yaml);
        assert!(
            !validate(&path).unwrap(),
            "fastest-in-country without target.country must fail validation"
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
            "target:\n      kind: secure-core\n      entry_country: fastest\n      exit_country: fastest\n",
            "target:\n      kind: secure-core\n      entry_country: fastest\n",
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
            "target:\n      kind: fastest-in-region\n      region: africa\n",
            "target:\n      kind: fastest-in-region\n      region: atlantis\n",
            1,
        );
        let path = temp_yaml("bad-region", &yaml);
        assert!(
            !validate(&path).unwrap(),
            "fastest-in-region with a region outside EXPECTED_REGIONS must fail validation"
        );
        fs::remove_file(&path).ok();
    }

    /// FU-5 (qa round-5 verdict): the kind vocabulary was checked only
    /// one-way — pinned kinds ⊆ ALLOWED_TARGET_KINDS — so a stray kind
    /// added to the constant passed the suite untouched. The CONTENTS of
    /// the vocabulary are part of the v1 contract and are pinned like the
    /// id set: exactly the five kinds the canonical document uses. This
    /// is also typoed_target_kind_fails' independent defender — its
    /// rejection power rests on the constant holding exactly these kinds.
    #[test]
    fn target_kind_vocabulary_contents_are_pinned() {
        assert_eq!(
            ALLOWED_TARGET_KINDS.len(),
            5,
            "the v1 catalog knows exactly five target kinds"
        );
        let vocabulary: BTreeSet<&str> = ALLOWED_TARGET_KINDS.iter().copied().collect();
        let expected: BTreeSet<&str> = BTreeSet::from([
            "fastest",
            "fastest-in-country",
            "fastest-in-region",
            "random",
            "secure-core",
        ]);
        assert_eq!(
            vocabulary, expected,
            "ALLOWED_TARGET_KINDS must stay exactly the v1 catalog's kinds"
        );
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

    /// The golden table pins exactly the canonical id set (the retired
    /// canonical_target_kind_map/canonical_override_map coverage style):
    /// one entry per built-in, no strays, no gaps — so the golden rule
    /// cannot silently stop covering a canonical group, and cannot grow
    /// an entry for an id outside the pinned set.
    #[test]
    fn golden_table_pins_exactly_the_canonical_ids() {
        let ids: BTreeSet<&str> = EXPECTED_GROUP_IDS.iter().copied().collect();
        let golden_ids: BTreeSet<&str> = GOLDEN_GROUP_ENTRIES.iter().map(|(id, _)| *id).collect();
        assert_eq!(
            golden_ids, ids,
            "GOLDEN_GROUP_ENTRIES must cover exactly the canonical ids"
        );
        // Every rendering must itself name its id: the per-id comparison
        // keys on the tuple, and a rendering whose embedded id disagrees
        // with its key would compare against the wrong entry forever.
        for (id, rendered) in GOLDEN_GROUP_ENTRIES {
            let entry: serde_json::Value = serde_norway::from_str(rendered)
                .unwrap_or_else(|err| panic!("golden entry `{id}` is not valid YAML: {err}"));
            assert_eq!(
                entry.get("id").and_then(serde_json::Value::as_str),
                Some(*id),
                "golden entry `{id}` must render an entry whose id field is `{id}`"
            );
        }
    }

    /// TEST-ONLY crosscheck (the canonical_test_inventory_matches_the_prd
    /// style): the GATE never reads the real document to validate itself —
    /// the pinned golden is its single authority — but this test renders
    /// the REAL docs/connection-groups.yaml with the same function and
    /// asserts byte equality with the constant, so `cargo test` catches a
    /// document edit that forgot the constant (or vice versa) even before
    /// `cargo xtask all` runs. A deliberate contract change edits the
    /// document AND regenerates the constant; this test is the
    /// regeneration discipline.
    #[test]
    fn real_document_matches_the_golden_table() {
        let path = crate::workspace_root()
            .expect("cannot derive the workspace root")
            .join("docs")
            .join("connection-groups.yaml");
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let raw: serde_json::Value = serde_norway::from_str(&text)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));
        let violations = check_golden_groups_table(&raw);
        assert!(
            violations.is_empty(),
            "docs/connection-groups.yaml drifted from GOLDEN_GROUP_ENTRIES — a \
             deliberate contract change regenerates the constant: {violations:?}"
        );
    }

    #[test]
    fn unknown_override_key_fails() {
        let yaml = good_groups_yaml().replacen(
            "overrides: {}\n    sources: [proton_default_connection, proton_connection_profiles]",
            "overrides: {color: red}\n    sources: [proton_default_connection, proton_connection_profiles]",
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
