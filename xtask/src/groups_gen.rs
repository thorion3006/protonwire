//! `cargo xtask groups-gen [--check]` — generates the core-owned
//! connection-group registry (`crates/core/src/groups/registry.rs`,
//! FR-23I) from `docs/connection-groups.yaml` and the vendored UN M49
//! snapshot.
//!
//! Three gates protect generation (the S13 validation stays THE gate —
//! this tool strengthens consumption, it never weakens validation):
//!
//! 1. the document must pass the golden groups table
//!    ([`crate::groups::check_golden_groups_table`]): generation from
//!    a drifted catalog is refused outright;
//! 1b. the document's `regional_taxonomy` must pass the S13 taxonomy
//!    pin ([`crate::groups::check_taxonomy`]) — the verdict round's
//!    P2-1: the golden table covers only `groups`, so a drifted
//!    taxonomy passed both other gates and rewrote the registry until
//!    this gate refused it too;
//! 2. the vendored CSV must pass `m49-verify`'s row contract against
//!    the document's own taxonomy before its country→region rows are
//!    embedded (FR-23O: runtime reads generated code, never the CSV).
//!
//! `--check` (wired into `cargo xtask all`) writes nothing and fails
//! when the committed registry is stale or missing — hand edits do not
//! survive CI.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

use crate::{Reporter, groups, m49};

const REGISTRY_REL: &str = "crates/core/src/groups/registry.rs";
const DEFAULT_SNAPSHOT_PATH: &str = "resources/geo/un-m49.csv";
/// rustfmt's default budgets — the generator emits pre-formatted code
/// the fmt gate must accept, so it makes the same inline/multiline
/// calls rustfmt makes: a literal whose bracketed width meets the
/// budget stays on one line, otherwise it breaks across lines.
const ARRAY_WIDTH: usize = 60;
const STRUCT_LIT_WIDTH: usize = 18;

pub fn run(root: &Path, check: bool) -> Result<bool> {
    let yaml_path = root.join("docs").join("connection-groups.yaml");
    let text = fs::read_to_string(&yaml_path)
        .with_context(|| format!("failed to read {}", yaml_path.display()))?;
    let doc: GenFile = serde_norway::from_str(&text)
        .with_context(|| format!("failed to parse {}", yaml_path.display()))?;
    let snapshot_rel = doc
        .regional_taxonomy
        .as_ref()
        .and_then(|taxonomy| taxonomy.vendored_snapshot.as_ref())
        .and_then(|snapshot| snapshot.required_path.clone())
        .unwrap_or_else(|| DEFAULT_SNAPSHOT_PATH.to_owned());
    let csv_path = root.join(&snapshot_rel);
    let out_path = root.join(REGISTRY_REL);
    generate_at(&text, &yaml_path, &csv_path, &out_path, check)
}

/// Full-fidelity view of the catalog for code generation. The
/// VALIDATION structs in [`crate::groups`] deliberately deserialize
/// only what their rules consult (the golden-table rule covers every
/// other field against the raw document); the generator needs every
/// field the registry carries, so it owns this second, complete view.
/// Fidelity is not a risk: gate 1 already proved the document equals
/// the golden rendering.
#[derive(Deserialize)]
struct GenFile {
    groups: Vec<GenGroup>,
    regional_taxonomy: Option<groups::RegionalTaxonomy>,
}

#[derive(Deserialize)]
struct GenGroup {
    id: String,
    label: String,
    origin: String,
    definition_source: String,
    entitlement: String,
    immutable: bool,
    target: GenTarget,
    ranking_policy: String,
    allowed_ranking_overrides: Option<Vec<String>>,
    overrides: Option<BTreeMap<String, String>>,
    sources: Vec<String>,
}

#[derive(Deserialize, Default)]
struct GenTarget {
    kind: Option<String>,
    connection_type: Option<String>,
    country: Option<String>,
    region: Option<String>,
    entry_country: Option<String>,
    exit_country: Option<String>,
    exclude_physical_country: Option<bool>,
    selection_authority: Option<String>,
}

/// Generates (or checks) the registry. Gates run first; a refused
/// generation never touches `out_path`.
fn generate_at(
    yaml_text: &str,
    yaml_path: &Path,
    csv_path: &Path,
    out_path: &Path,
    check: bool,
) -> Result<bool> {
    let mut reporter = Reporter::new("groups-gen");

    // Gate 1 — the S13 golden-document equality on the raw text.
    let raw: serde_json::Value = serde_norway::from_str(yaml_text)
        .with_context(|| format!("failed to parse {}", yaml_path.display()))?;
    let golden = groups::check_golden_groups_table(&raw);
    reporter.rule(
        "source document passes the golden groups table (S13)",
        &golden,
    );

    // Gate 1b — the S13 taxonomy pin (the verdict round's P2-1: the
    // golden table covers only `groups`; a drifted `regional_taxonomy`
    // passed BOTH gates and rewrote the registry, caught only by
    // groups-validate elsewhere in `xtask all`. Standalone
    // `groups-gen` now refuses the same drift itself).
    let validation_doc: groups::GroupsFile = serde_norway::from_str(yaml_text)
        .with_context(|| format!("failed to parse {}", yaml_path.display()))?;
    let taxonomy = groups::check_taxonomy(&validation_doc);
    reporter.rule("regional taxonomy passes the S13 pin", &taxonomy);

    // Gate 2 — m49-verify's row contract on the actual CSV bytes,
    // against the taxonomy the SAME document declares.
    let doc: GenFile = serde_norway::from_str(yaml_text)
        .with_context(|| format!("failed to parse {}", yaml_path.display()))?;
    let mapping = m49::region_mapping(doc.regional_taxonomy.as_ref());
    let bytes =
        fs::read(csv_path).with_context(|| format!("failed to read {}", csv_path.display()))?;
    let outcome = m49::verify_csv(&bytes, &mapping);
    reporter.rule(
        "vendored UN M49 snapshot verifies against the taxonomy",
        &outcome.violations,
    );

    if !golden.is_empty() || !taxonomy.is_empty() || !outcome.violations.is_empty() {
        return Ok(reporter
            .finish("generation refused: the source documents failed their validation gates"));
    }

    let rows = country_rows(&bytes)?;
    let rendered = render(&doc, &rows)?;

    if check {
        let violations = match fs::read(out_path) {
            Ok(existing) if existing == rendered.as_bytes() => Vec::new(),
            Ok(_) => vec![format!(
                "{} is stale; rerun `cargo xtask groups-gen` (the yaml + snapshot are the \
                 source of truth — hand edits are overwritten)",
                out_path.display()
            )],
            Err(_) => vec![format!(
                "{} is missing; rerun `cargo xtask groups-gen`",
                out_path.display()
            )],
        };
        reporter.rule("generated registry is up to date", &violations);
        return Ok(reporter.finish(&format!(
            "registry {REGISTRY_REL} against {} + {}",
            yaml_path.display(),
            csv_path.display()
        )));
    }

    fs::write(out_path, &rendered)
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    println!(
        "PASS [groups-gen] wrote {} ({} group(s), {} country membership row(s))",
        out_path.display(),
        doc.groups.len(),
        rows.len()
    );
    Ok(true)
}

/// (ISO, m49, region) rows from the verified CSV, in file (ascending
/// ISO) order. Only called after `verify_csv` passed.
fn country_rows(bytes: &[u8]) -> Result<Vec<(String, String, String)>> {
    let text = std::str::from_utf8(bytes).with_context(|| "the snapshot must be valid UTF-8")?;
    let mut rows = Vec::new();
    for (index, line) in text.split('\n').enumerate().skip(1) {
        if line.is_empty() {
            continue;
        }
        let fields = m49::parse_csv_line(line).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            fields.len() == 5,
            "row {index}: expected 5 fields, got {}",
            fields.len()
        );
        rows.push((fields[2].clone(), fields[1].clone(), fields[4].clone()));
    }
    Ok(rows)
}

/// Renders the registry source. Deterministic: the same document and
/// rows always render byte-identically (groups in document order,
/// regions in map order, countries in CSV order).
fn render(doc: &GenFile, rows: &[(String, String, String)]) -> Result<String> {
    let regions = doc
        .regional_taxonomy
        .as_ref()
        .and_then(|taxonomy| taxonomy.primary_regions.as_ref())
        .ok_or_else(|| anyhow!("regional_taxonomy.primary_regions is missing"))?;
    anyhow::ensure!(!doc.groups.is_empty(), "the catalog carries no groups");

    let mut seen_ids = std::collections::BTreeSet::new();
    for group in &doc.groups {
        anyhow::ensure!(
            seen_ids.insert(group.id.as_str()),
            "duplicate id {}",
            group.id
        );
    }

    // Region-name set + membership sanity: every declared region must
    // gain members from the snapshot, and every snapshot row must name
    // a declared region (verify_csv already pinned row↔taxonomy
    // agreement; these make the emission itself total).
    let mut members: BTreeMap<&str, usize> =
        regions.keys().map(|name| (name.as_str(), 0)).collect();
    for (iso, _m49, region) in rows {
        let count = members
            .get_mut(region.as_str())
            .with_context(|| format!("country `{iso}` maps to undeclared region `{region}`"))?;
        *count += 1;
    }
    for (name, count) in &members {
        anyhow::ensure!(*count > 0, "region `{name}` has no member countries");
    }

    let mut out = String::new();
    out.push_str(
        "//! GENERATED by `cargo xtask groups-gen` — DO NOT EDIT BY HAND.\n\
         //!\n\
         //! Source of truth: `docs/connection-groups.yaml` (generation refuses a\n\
         //! document that fails the S13 golden-table validation or the S13\n\
         //! taxonomy pin) and the vendored UN M49 snapshot\n\
         //! `resources/geo/un-m49.csv` (checksum-gated by `cargo xtask\n\
         //! m49-verify`; generation embeds only a snapshot that verifies).\n\
         //! `cargo xtask all` checks this file's freshness; the core suite\n\
         //! pins its semantics (T-28/T-29/T-30/T-33).\n\n",
    );
    out.push_str(
        "use super::{\n    ConnectionType, DefinitionSource, GroupEntitlement, GroupEntry, GroupOrigin,\n    GroupRankingPolicy, GroupTarget, RegionEntry,\n};\nuse crate::selection::ProtocolConstraint;\n\n",
    );

    // `#[rustfmt::skip]` on each const: the generator owns the file's
    // canonical form (byte-stable, enforced by --check); the formatter
    // never fights it over generated-data layout.
    out.push_str("#[rustfmt::skip]\npub(crate) const REGISTRY: &[GroupEntry] = &[\n");
    for group in &doc.groups {
        out.push_str(&render_group(group, regions)?);
    }
    out.push_str("];\n\n");

    out.push_str("#[rustfmt::skip]\npub(crate) const REGIONS: &[RegionEntry] = &[\n");
    for (name, definition) in regions {
        let codes = definition.m49_codes.as_deref().unwrap_or_default();
        let fields = vec![format!("name: {name:?}"), format!("m49_codes: &{codes:?}")];
        out.push_str(&format!(
            "    {},\n",
            emit_struct_literal("RegionEntry", &fields, 4)
        ));
    }
    out.push_str("];\n\n");

    out.push_str("#[rustfmt::skip]\npub(crate) const COUNTRY_REGIONS: &[(&str, &str)] = &[\n");
    for (iso, _m49, region) in rows {
        out.push_str(&format!("    ({iso:?}, {region:?}),\n"));
    }
    out.push_str("];\n");
    Ok(out)
}

/// Renders one `GroupEntry`. Every yaml value that has no typed mapping
/// refuses generation naming the group and the value — a future
/// contract change must extend the generator deliberately, never emit
/// lossy data.
fn render_group(
    group: &GenGroup,
    regions: &BTreeMap<String, groups::PrimaryRegion>,
) -> Result<String> {
    let id = group.id.as_str();
    let origin = match group.origin.as_str() {
        "proton" => "GroupOrigin::Proton",
        "protonwire" => "GroupOrigin::Protonwire",
        other => bail!("{id}: unmappable origin `{other}`"),
    };
    anyhow::ensure!(
        id.split(':').next() == Some(group.origin.as_str()),
        "{id}: the id namespace must match origin `{}`",
        group.origin
    );
    let definition_source = match group.definition_source.as_str() {
        "proton-api" => "DefinitionSource::ProtonApi",
        "official-client-compat" => "DefinitionSource::OfficialClientCompat",
        "protonwire" => "DefinitionSource::Protonwire",
        other => bail!("{id}: unmappable definition_source `{other}`"),
    };
    let entitlement = match group.entitlement.as_str() {
        "plan-dependent" => "GroupEntitlement::PlanDependent",
        "target-and-feature-dependent" => "GroupEntitlement::TargetAndFeatureDependent",
        "paid-location-selection" => "GroupEntitlement::PaidLocationSelection",
        other => bail!("{id}: unmappable entitlement `{other}`"),
    };
    let ranking_policy = ranking_variant(&group.ranking_policy)
        .with_context(|| format!("{id}: unmappable ranking_policy"))?;
    let allowed = group
        .allowed_ranking_overrides
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|token| ranking_variant(token).with_context(|| format!("{id}: unmappable override")))
        .collect::<Result<Vec<&'static str>>>()?;

    let target = &group.target;
    let kind = target
        .kind
        .as_deref()
        .with_context(|| format!("{id}: target.kind is missing"))?;
    // (variant, "field: value" renders). The literal is emitted inline
    // when its field content fits rustfmt's struct-literal budget (18)
    // — the same call rustfmt itself makes — and multiline otherwise,
    // so generated bytes are always fmt-canonical.
    let (variant, fields, kind_takes_connection_type): (&str, Vec<String>, bool) = match kind {
        "fastest" => (
            "Fastest",
            vec![format!(
                "exclude_physical_country: {}",
                target.exclude_physical_country.unwrap_or(false)
            )],
            true,
        ),
        "fastest-in-country" => {
            let country = target
                .country
                .as_deref()
                .with_context(|| format!("{id}: fastest-in-country needs target.country"))?;
            (
                "FastestInCountry",
                vec![format!("country: {country:?}")],
                true,
            )
        }
        "fastest-in-region" => {
            let region = target
                .region
                .as_deref()
                .with_context(|| format!("{id}: fastest-in-region needs target.region"))?;
            anyhow::ensure!(
                regions.contains_key(region),
                "{id}: target.region `{region}` is not a primary region"
            );
            (
                "FastestInRegion",
                vec![format!("region: {region:?}")],
                false,
            )
        }
        "random" => ("Random", Vec::new(), true),
        "secure-core" => {
            let entry = target
                .entry_country
                .as_deref()
                .with_context(|| format!("{id}: secure-core needs target.entry_country"))?;
            let exit = target
                .exit_country
                .as_deref()
                .with_context(|| format!("{id}: secure-core needs target.exit_country"))?;
            (
                "SecureCore",
                vec![
                    format!("entry_country: {entry:?}"),
                    format!("exit_country: {exit:?}"),
                ],
                false,
            )
        }
        other => bail!("{id}: unmappable target.kind `{other}`"),
    };
    let target_path = format!("GroupTarget::{variant}");
    let target_code = if fields.is_empty() {
        target_path
    } else {
        emit_struct_literal(&target_path, &fields, 8)
    };
    let connection_type = match target.connection_type.as_deref() {
        Some("standard") if kind_takes_connection_type => "Some(ConnectionType::Standard)",
        None if !kind_takes_connection_type => "None",
        // A kind that normally names a connection type without one (or
        // an unknown token) is a catalog shape change: refuse.
        Some(other) => bail!("{id}: unmappable target.connection_type `{other}`"),
        None => bail!("{id}: target.connection_type is required for kind `{kind}`"),
    };

    let mut protocol_override = "None".to_owned();
    let mut connection_overrides: Vec<(String, String)> = Vec::new();
    for (key, value) in group.overrides.iter().flatten() {
        match key.as_str() {
            "protocol" => {
                protocol_override = match value.as_str() {
                    "wireguard-udp" => "Some(ProtocolConstraint::WireguardUdp)".to_owned(),
                    "wireguard-tcp" => "Some(ProtocolConstraint::WireguardTcp)".to_owned(),
                    "stealth" => "Some(ProtocolConstraint::Stealth)".to_owned(),
                    other => bail!("{id}: unmappable protocol override `{other}`"),
                };
            }
            "nat" | "lan_access" => connection_overrides.push((key.clone(), value.clone())),
            other => bail!(
                "{id}: override key `{other}` has no generation mapping — extend the \
                 generator deliberately"
            ),
        }
    }

    let mut out = String::new();
    // A plain comment: doc comments on const-array elements are not
    // item docs and rustc warns them unused.
    out.push_str(&format!(
        "    // {} — {} / {}.\n",
        group.label, group.origin, group.definition_source
    ));
    out.push_str("    GroupEntry {\n");
    out.push_str(&format!("        id: {id:?},\n"));
    out.push_str(&format!("        label: {:?},\n", group.label));
    out.push_str(&format!("        origin: {origin},\n"));
    out.push_str(&format!(
        "        definition_source: {definition_source},\n"
    ));
    out.push_str(&format!("        entitlement: {entitlement},\n"));
    out.push_str(&format!("        immutable: {},\n", group.immutable));
    out.push_str(&format!("        connection_type: {connection_type},\n"));
    out.push_str(&format!("        target: {target_code},\n"));
    out.push_str(&format!("        ranking_policy: {ranking_policy},\n"));
    out.push_str(&format!(
        "        allowed_ranking_overrides: {},\n",
        emit_variant_list(&allowed, 8)
    ));
    out.push_str(&format!(
        "        protocol_override: {protocol_override},\n"
    ));
    let override_items: Vec<String> = connection_overrides
        .iter()
        .map(|(key, value)| format!("({key:?}, {value:?})"))
        .collect();
    let override_refs: Vec<&str> = override_items.iter().map(String::as_str).collect();
    out.push_str(&format!(
        "        connection_overrides: {},\n",
        emit_raw_list(&override_refs, 8)
    ));
    out.push_str(&format!(
        "        selection_authority: {},\n",
        match &target.selection_authority {
            Some(authority) => format!("Some({authority:?})"),
            None => "None".to_owned(),
        }
    ));
    let source_items: Vec<String> = group
        .sources
        .iter()
        .map(|source| format!("{source:?}"))
        .collect();
    let source_refs: Vec<&str> = source_items.iter().map(String::as_str).collect();
    out.push_str(&format!(
        "        sources: {},\n",
        emit_raw_list(&source_refs, 8)
    ));
    out.push_str("    },\n");
    Ok(out)
}

/// The typed variant for a catalog ranking-policy token.
fn ranking_variant(token: &str) -> Result<&'static str> {
    match token {
        "proton-score" => Ok("GroupRankingPolicy::ProtonScore"),
        "balanced" => Ok("GroupRankingPolicy::Balanced"),
        "load" => Ok("GroupRankingPolicy::Load"),
        "latency" => Ok("GroupRankingPolicy::Latency"),
        "random-country-then-server" => Ok("GroupRankingPolicy::RandomCountryThenServer"),
        other => bail!("unmappable ranking policy `{other}`"),
    }
}

/// `Path { field: value, ... }` inline when the bracketed content
/// meets rustfmt's struct-literal budget, multiline otherwise. Fields
/// are pre-rendered `name: value` strings.
fn emit_struct_literal(path: &str, fields: &[String], indent: usize) -> String {
    let content = fields.join(", ");
    if content.len() + 2 <= STRUCT_LIT_WIDTH {
        return format!("{path} {{ {content} }}");
    }
    let mut out = format!("{path} {{\n");
    for field in fields {
        out.push_str(&format!("{:indent$}{field},\n", "", indent = indent + 4));
    }
    out.push_str(&format!("{:indent$}}}", "", indent = indent));
    out
}

/// `&[X]`, `&[X, Y]`, or a multiline form when the bracketed content
/// exceeds rustfmt's array width. `variants` are fully qualified paths.
fn emit_variant_list(variants: &[&str], indent: usize) -> String {
    if variants.is_empty() {
        return "&[]".to_owned();
    }
    emit_raw_list(variants, indent)
}

/// `&["a"]` / `&[("k", "v")]` lists with the same budget rule; items
/// are pre-rendered strings.
fn emit_raw_list(items: &[&str], indent: usize) -> String {
    if items.is_empty() {
        return "&[]".to_owned();
    }
    let joined = items.join(", ");
    if joined.len() + 2 <= ARRAY_WIDTH {
        return format!("&[{joined}]");
    }
    let mut out = "&[\n".to_owned();
    for item in items {
        out.push_str(&format!("{:indent$}{item},\n", "", indent = indent + 4));
    }
    out.push_str(&format!("{:indent$}]", "", indent = indent));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn real_sources(tag: &str) -> (PathBuf, PathBuf, PathBuf, String) {
        let root = crate::workspace_root().expect("workspace root");
        let yaml = root.join("docs").join("connection-groups.yaml");
        let text = fs::read_to_string(&yaml).unwrap();
        let csv = root.join("resources").join("geo").join("un-m49.csv");
        // Per-test unique: the suite runs tests in parallel inside ONE
        // process, so process::id() alone collides.
        let out =
            std::env::temp_dir().join(format!("xtask-groups-gen-{tag}-{}", std::process::id()));
        (yaml, csv, out, text)
    }

    /// The canonical ids come from THE S13 pin (`groups::EXPECTED_GROUP_IDS`)
    /// — no mirror list here: the registry must carry each pinned id, and a
    /// pin edit flows into this check without a second copy to drift.
    use crate::groups::EXPECTED_GROUP_IDS as CANONICAL_IDS;

    #[test]
    fn generating_from_the_real_sources_is_complete_and_deterministic() {
        let (yaml, csv, out, text) = real_sources("happy");
        let _ = fs::remove_file(&out);
        assert!(
            generate_at(&text, &yaml, &csv, &out, false).unwrap(),
            "the real sources must generate cleanly"
        );
        let rendered = fs::read_to_string(&out).unwrap();
        for id in CANONICAL_IDS {
            assert!(
                rendered.contains(&format!("id: \"{id}\"")),
                "the registry must carry `{id}`"
            );
        }
        for region in [
            "africa",
            "asia",
            "europe",
            "north-america",
            "south-america",
            "oceania",
        ] {
            assert!(
                rendered.contains(&format!("name: \"{region}\"")),
                "the registry must carry region `{region}`"
            );
        }
        // Membership extremes (CSV is ISO-ascending): first and last row.
        assert!(rendered.contains("(\"AD\", \"europe\")"));
        assert!(rendered.contains("(\"ZW\", \"africa\")"));
        // The composite region renders all three of its codes.
        assert!(rendered.contains("&[\"021\", \"013\", \"029\"]"));

        // Deterministic: a second run is byte-identical, and check
        // mode is clean against exactly what was written.
        assert!(generate_at(&text, &yaml, &csv, &out, false).unwrap());
        assert_eq!(fs::read_to_string(&out).unwrap(), rendered);
        assert!(generate_at(&text, &yaml, &csv, &out, true).unwrap());
        let _ = fs::remove_file(&out);
    }

    /// Gate 1: a drifted document (one the S13 golden table rejects)
    /// must never reach the writer.
    #[test]
    fn a_drifted_yaml_refuses_generation_without_writing() {
        let (yaml, csv, out, text) = real_sources("drift-yaml");
        let _ = fs::remove_file(&out);
        let drifted = text.replacen("label: Fastest country", "label: Fastest nation", 1);
        assert_ne!(drifted, text, "fixture must actually drift");
        assert!(!generate_at(&drifted, &yaml, &csv, &out, false).unwrap());
        assert!(
            !out.exists(),
            "a refused generation must not touch the output file"
        );
    }

    /// Gate 2: a CSV that fails the m49 row contract (GB's region moved
    /// to asia with the asia code — taxonomy-consistent enough for the
    /// row rules, caught by the per-country pin) refuses generation.
    #[test]
    fn a_drifted_csv_refuses_generation_without_writing() {
        let (yaml, _csv, out, text) = real_sources("drift-csv");
        let _ = fs::remove_file(&out);
        let tampered_csv =
            std::env::temp_dir().join(format!("xtask-groups-gen-csv-{}", std::process::id()));
        fs::write(&tampered_csv, "m49_region_code,m49_code,iso_3166_1_alpha_2,name,region\n142,826,GB,United Kingdom,asia\n").unwrap();
        assert!(
            !generate_at(&text, &yaml, &tampered_csv, &out, false).unwrap(),
            "a snapshot failing m49-verify must refuse generation"
        );
        assert!(!out.exists());
        let _ = fs::remove_file(&tampered_csv);
    }

    #[test]
    fn check_mode_flags_missing_and_stale_registries() {
        let (yaml, csv, out, text) = real_sources("check");
        let _ = fs::remove_file(&out);
        assert!(
            !generate_at(&text, &yaml, &csv, &out, true).unwrap(),
            "a missing registry must fail --check"
        );
        assert!(generate_at(&text, &yaml, &csv, &out, false).unwrap());
        let mut stale = fs::read_to_string(&out).unwrap();
        stale.push_str("// hand edit\n");
        fs::write(&out, &stale).unwrap();
        assert!(
            !generate_at(&text, &yaml, &csv, &out, true).unwrap(),
            "a hand-edited registry must fail --check"
        );
        let _ = fs::remove_file(&out);
    }

    /// The unmappable-value refusals are unreachable for any document
    /// that passes the golden table (the table pins the values), so
    /// they are pinned at the render seam: a future contract change
    /// that regenerates the golden table must extend the generator
    /// deliberately, never emit lossy data.
    #[test]
    fn unmappable_values_refuse_at_the_render_seam() {
        let group = |overrides: Option<BTreeMap<String, String>>| GenGroup {
            id: "proton:test".to_owned(),
            label: "Test".to_owned(),
            origin: "proton".to_owned(),
            definition_source: "official-client-compat".to_owned(),
            entitlement: "plan-dependent".to_owned(),
            immutable: true,
            target: GenTarget {
                kind: Some("fastest".to_owned()),
                connection_type: Some("standard".to_owned()),
                exclude_physical_country: Some(false),
                ..GenTarget::default()
            },
            ranking_policy: "proton-score".to_owned(),
            allowed_ranking_overrides: None,
            overrides,
            sources: vec!["proton_default_connection".to_owned()],
        };
        let mut regions = BTreeMap::new();
        regions.insert(
            "africa".to_owned(),
            groups::PrimaryRegion {
                m49_codes: Some(vec!["002".to_owned()]),
            },
        );

        let mut protocol = group(None);
        protocol.overrides = Some(BTreeMap::from([(
            "protocol".to_owned(),
            "openvpn".to_owned(),
        )]));
        assert!(render_group(&protocol, &regions).is_err());

        let mut extra_key = group(None);
        extra_key.overrides = Some(BTreeMap::from([("color".to_owned(), "red".to_owned())]));
        assert!(render_group(&extra_key, &regions).is_err());

        let mut bad_origin = group(None);
        bad_origin.origin = "official".to_owned();
        assert!(render_group(&bad_origin, &regions).is_err());

        let mut missing_country = group(None);
        missing_country.target = GenTarget {
            kind: Some("fastest-in-country".to_owned()),
            ..GenTarget::default()
        };
        assert!(render_group(&missing_country, &regions).is_err());

        let mut unknown_region = group(None);
        unknown_region.target = GenTarget {
            kind: Some("fastest-in-region".to_owned()),
            region: Some("atlantis".to_owned()),
            ..GenTarget::default()
        };
        assert!(render_group(&unknown_region, &regions).is_err());
    }
}
