//! `cargo xtask manifest-validate` — validates `docs/official-parity.yaml`
//! (schema version 3) against the parity-manifest contract.
//!
//! Enforces the pinned upstream revisions/checksums, the status vocabulary,
//! capability id/area/owner/source/test invariants, and the T-19 evidence rule
//! (`verified` capabilities must carry `verified_at`, tests, and sources).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::{Reporter, expect_value, is_capability_id, is_git_revision, is_sha256_hex, is_test_id};

const PROTON_REVISION: &str = "12e7755a112f59b7b843da79290b3de25febf653";

/// The six pinned official-client baselines that must record a git revision.
const OFFICIAL_UPSTREAMS: &[&str] = &[
    "official_linux_cli",
    "official_linux_gui",
    "official_linux_api_core",
    "official_android_app",
    "official_windows_app",
    "official_apple_app",
];

const REQUIRED_STATUSES: &[&str] = &[
    "required",
    "implemented",
    "verified",
    "blocked-upstream",
    "not-applicable",
    "legacy-excluded",
];

const ALLOWED_OWNERS: &[&str] = &[
    "protonwire-core",
    "protonwire-frontend-api",
    "protonwire-client",
    "protonwire-ipc",
    "protonwire-api",
    "protonwire-protocol",
    "protonwire-net",
    "protonwire-policy",
    "protonwire-pf",
    "protonwire-store",
    "protonwire-daemon",
    "protonwire-credential-agent",
    "protonwire-cli",
    "protonwire-tui",
    "protonwire-gui",
    "none",
    "packaging",
];

#[derive(Deserialize)]
struct Manifest {
    schema_version: Option<i64>,
    baseline: Option<serde_json::Value>,
    client_contract: Option<serde_json::Value>,
    upstream: Option<BTreeMap<String, UpstreamEntry>>,
    status_definitions: Option<BTreeMap<String, String>>,
    sources: Option<BTreeMap<String, serde_json::Value>>,
    capabilities: Option<Vec<Capability>>,
}

#[derive(Deserialize)]
struct UpstreamEntry {
    version: Option<String>,
    revision: Option<String>,
    checksum_sha256: Option<String>,
}

#[derive(Deserialize)]
struct Capability {
    id: Option<String>,
    area: Option<String>,
    status: Option<String>,
    behavior: Option<String>,
    owner: Option<String>,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    tests: Vec<String>,
    verified_at: Option<String>,
    blocker: Option<String>,
}

pub fn run(root: &Path) -> Result<bool> {
    // The committed lockfile is the resolution authority the recorded
    // upstream digests are compared against (Codex PR review round 2,
    // finding 6): an unreadable or unparseable Cargo.lock is a hard
    // error, not a skipped rule.
    let lock = Lockfile::read(&root.join("Cargo.lock"))?;
    validate(&root.join("docs").join("official-parity.yaml"), &lock)
}

fn validate(path: &Path, lock: &Lockfile) -> Result<bool> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let doc: Manifest = serde_norway::from_str(&text)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let mut reporter = Reporter::new("manifest-validate");
    reporter.rule("schema_version == 3", &check_schema_version(&doc));
    reporter.rule(
        "required top-level keys present",
        &check_top_level_keys(&doc),
    );
    reporter.rule(
        "status_definitions completeness",
        &check_status_definitions(&doc),
    );
    reporter.rule("upstream pins", &check_upstream(&doc, lock));
    reporter.rule("capabilities", &check_capabilities(&doc));

    let total = doc.capabilities.as_ref().map_or(0, Vec::len);
    let per_status = status_counts(&doc)
        .iter()
        .map(|(status, count)| format!("{status}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    let summary = format!("{total} capabilities; per status: {per_status}");
    Ok(reporter.finish(&summary))
}

fn check_schema_version(doc: &Manifest) -> Vec<String> {
    match doc.schema_version {
        Some(3) => Vec::new(),
        Some(other) => vec![format!("schema_version must be 3, got {other}")],
        None => vec!["schema_version is missing".to_string()],
    }
}

fn check_top_level_keys(doc: &Manifest) -> Vec<String> {
    let mut violations = Vec::new();
    let checks = [
        ("baseline", doc.baseline.is_none()),
        ("client_contract", doc.client_contract.is_none()),
        ("upstream", doc.upstream.is_none()),
        ("status_definitions", doc.status_definitions.is_none()),
        ("sources", doc.sources.is_none()),
        ("capabilities", doc.capabilities.is_none()),
    ];
    for (key, missing) in checks {
        if missing {
            violations.push(format!("top-level key `{key}` is missing"));
        }
    }
    violations
}

fn check_status_definitions(doc: &Manifest) -> Vec<String> {
    let Some(definitions) = &doc.status_definitions else {
        return vec!["status_definitions is missing".to_string()];
    };
    let mut violations = Vec::new();
    for status in REQUIRED_STATUSES {
        if !definitions.contains_key(*status) {
            violations.push(format!("status_definitions is missing `{status}`"));
        }
    }
    // Codex PR review round 2, finding 5: the vocabulary is frozen, not
    // merely minimal. check_capabilities builds its accepted set from ALL
    // definition keys, so an extra definition silently legalizes invented
    // statuses for capabilities (`waived`, ...) — exactly the drift the
    // fixed parity-state vocabulary exists to prevent.
    let frozen: BTreeSet<&str> = REQUIRED_STATUSES.iter().copied().collect();
    let defined: BTreeSet<&str> = definitions.keys().map(String::as_str).collect();
    for status in defined.difference(&frozen) {
        violations.push(format!(
            "status_definitions contains `{status}`, which is outside the frozen vocabulary {REQUIRED_STATUSES:?}"
        ));
    }
    violations
}
/// The recorded upstream digest must EQUAL the lockfile's checksum for the
/// pinned version (Codex PR review round 2, finding 6): the lockfile is the
/// resolution authority, so a well-formed-but-different digest in the
/// manifest is supply-chain drift the hex-shape check cannot detect. A
/// missing lockfile entry fails rather than passing vacuously.
fn expect_lock_checksum(recorded: Option<&str>, locked: Option<&str>, what: &str) -> Vec<String> {
    match (recorded, locked) {
        (Some(recorded), Some(locked)) if recorded == locked => Vec::new(),
        (Some(recorded), Some(locked)) => vec![format!(
            "{what} `{recorded}` disagrees with the Cargo.lock checksum `{locked}`"
        )],
        (Some(_), None) => vec![format!(
            "{what} cannot be verified: Cargo.lock records no checksum for the pinned version"
        )],
        (None, _) => vec![format!("{what} is missing")],
    }
}

fn expect_checksum(actual: Option<&str>, what: &str) -> Option<String> {
    match actual {
        Some(value) if is_sha256_hex(value) => None,
        Some(value) => Some(format!(
            "{what} must be 64 lowercase hex characters, got `{value}`"
        )),
        None => Some(format!("{what} is missing")),
    }
}

fn expect_revision(actual: Option<&str>, what: &str) -> Option<String> {
    match actual {
        Some(value) if is_git_revision(value) => None,
        Some(value) => Some(format!(
            "{what} must be a 40-character git revision, got `{value}`"
        )),
        None => Some(format!("{what} is missing")),
    }
}

/// The committed root lockfile — the resolution authority the recorded
/// upstream digests are compared against (Codex PR review round 2,
/// finding 6; PRD 6.5 makes Cargo.lock authoritative for the pins).
struct Lockfile {
    /// `(name, version)` → checksum, for packages that carry one (path
    /// and git dependencies record none).
    checksums: BTreeMap<(String, String), String>,
}

#[derive(Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    #[serde(default)]
    checksum: Option<String>,
}

#[derive(Deserialize)]
struct LockDocument {
    #[serde(default, rename = "package")]
    packages: Vec<LockPackage>,
}

impl Lockfile {
    /// Parses lockfile text (`[[package]]` entries, format v3/v4).
    fn parse(text: &str) -> Result<Self> {
        let doc: LockDocument =
            toml::from_str(text).with_context(|| "failed to parse Cargo.lock")?;
        Ok(Self {
            checksums: doc
                .packages
                .into_iter()
                .filter_map(|package| Some(((package.name, package.version), package.checksum?)))
                .collect(),
        })
    }

    /// Reads and parses the lockfile at `path`.
    fn read(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(&text)
    }

    /// The checksum recorded for `name` at `version`, if the lockfile
    /// entry carries one.
    fn checksum(&self, name: &str, version: &str) -> Option<&str> {
        self.checksums
            .get(&(name.to_owned(), version.to_owned()))
            .map(String::as_str)
    }
}

fn check_upstream(doc: &Manifest, lock: &Lockfile) -> Vec<String> {
    let mut violations = Vec::new();
    let Some(upstream) = &doc.upstream else {
        return vec!["upstream is missing".to_string()];
    };

    match upstream.get("protun") {
        Some(entry) => {
            violations.extend(expect_value(
                entry.version.as_deref(),
                "2.2.1",
                "upstream.protun.version",
            ));
            violations.extend(expect_value(
                entry.revision.as_deref(),
                PROTON_REVISION,
                "upstream.protun.revision",
            ));
        }
        None => violations.push("upstream.protun is missing".to_string()),
    }

    match upstream.get("muon") {
        Some(entry) => {
            violations.extend(expect_value(
                entry.version.as_deref(),
                "2.6.1",
                "upstream.muon.version",
            ));
            violations.extend(expect_checksum(
                entry.checksum_sha256.as_deref(),
                "upstream.muon.checksum_sha256",
            ));
            violations.extend(expect_lock_checksum(
                entry.checksum_sha256.as_deref(),
                lock.checksum("muon", "2.6.1"),
                "upstream.muon.checksum_sha256",
            ));
        }
        None => violations.push("upstream.muon is missing".to_string()),
    }

    match upstream.get("pvpnclient") {
        Some(entry) => {
            violations.extend(expect_value(
                entry.version.as_deref(),
                "3.0.3",
                "upstream.pvpnclient.version",
            ));
            violations.extend(expect_checksum(
                entry.checksum_sha256.as_deref(),
                "upstream.pvpnclient.checksum_sha256",
            ));
            violations.extend(expect_lock_checksum(
                entry.checksum_sha256.as_deref(),
                lock.checksum("pvpnclient", "3.0.3"),
                "upstream.pvpnclient.checksum_sha256",
            ));
        }
        None => violations.push("upstream.pvpnclient is missing".to_string()),
    }

    for name in OFFICIAL_UPSTREAMS {
        match upstream.get(*name) {
            Some(entry) => {
                violations.extend(expect_revision(
                    entry.revision.as_deref(),
                    &format!("upstream.{name}"),
                ));
            }
            None => violations.push(format!("upstream.{name} is missing")),
        }
    }

    // Any further upstream entry must also record a full git revision.
    for (name, entry) in upstream {
        if matches!(name.as_str(), "protun" | "muon" | "pvpnclient")
            || OFFICIAL_UPSTREAMS.contains(&name.as_str())
        {
            continue;
        }
        violations.extend(expect_revision(
            entry.revision.as_deref(),
            &format!("upstream.{name}"),
        ));
    }

    violations
}

fn check_capabilities(doc: &Manifest) -> Vec<String> {
    let mut violations = Vec::new();
    let Some(capabilities) = &doc.capabilities else {
        return vec!["capabilities is missing".to_string()];
    };
    if capabilities.is_empty() {
        return vec!["capabilities list must not be empty".to_string()];
    }

    let statuses: BTreeSet<&str> = doc
        .status_definitions
        .as_ref()
        .map(|definitions| definitions.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let sources: BTreeSet<&str> = doc
        .sources
        .as_ref()
        .map(|sources| sources.keys().map(String::as_str).collect())
        .unwrap_or_default();

    let mut seen = BTreeSet::new();
    for (index, capability) in capabilities.iter().enumerate() {
        if let Some(id) = &capability.id
            && !seen.insert(id.clone())
        {
            violations.push(format!("duplicate capability id `{id}`"));
        }
        violations.extend(check_capability(index, capability, &statuses, &sources));
    }
    violations
}

fn check_capability(
    index: usize,
    capability: &Capability,
    statuses: &BTreeSet<&str>,
    sources: &BTreeSet<&str>,
) -> Vec<String> {
    let mut violations = Vec::new();
    let label = capability
        .id
        .clone()
        .unwrap_or_else(|| format!("capability #{index}"));

    let Some(id) = &capability.id else {
        return vec![format!("{label}: `id` is missing")];
    };
    if !is_capability_id(id) {
        violations.push(format!("{label}: id must match ^[a-z0-9-]+\\.[a-z0-9-]+$"));
    }

    // The id namespace and the coarse area are intentionally distinct
    // vocabularies in this manifest (for example `protocol.smart` sits in
    // area `protocols`); only membership in the area vocabulary is checked.
    const KNOWN_AREAS: &[&str] = &[
        "account",
        "clients",
        "connection-groups",
        "connection-options",
        "diagnostics",
        "dns-filtering",
        "legacy",
        "linux-integration",
        "presentation",
        "profiles",
        "protection",
        "protocols",
        "security",
        "servers",
        "special-servers",
        "split-tunneling",
    ];
    match capability.area.as_deref() {
        Some(area) if KNOWN_AREAS.contains(&area) => {}
        Some(area) => violations.push(format!(
            "{label}: area `{area}` is not one of the known areas {KNOWN_AREAS:?}"
        )),
        None => violations.push(format!("{label}: `area` is missing")),
    }

    match capability.status.as_deref() {
        Some(status) if statuses.contains(status) => {}
        Some(status) => violations.push(format!(
            "{label}: status `{status}` is not defined in status_definitions"
        )),
        None => violations.push(format!("{label}: `status` is missing")),
    }

    match capability.behavior.as_deref().map(str::trim) {
        Some(behavior) if !behavior.is_empty() => {}
        Some(_) => violations.push(format!("{label}: behavior must not be empty")),
        None => violations.push(format!("{label}: `behavior` is missing")),
    }

    match capability.owner.as_deref() {
        Some(owner) if ALLOWED_OWNERS.contains(&owner) => {}
        Some(owner) => violations.push(format!("{label}: owner `{owner}` is not an allowed owner")),
        None => violations.push(format!("{label}: `owner` is missing")),
    }

    for source in &capability.sources {
        if !sources.contains(source.as_str()) {
            violations.push(format!(
                "{label}: source `{source}` is not a top-level source key"
            ));
        }
    }

    // `not-applicable` and `legacy-excluded` capabilities are out of scope
    // by definition and may legitimately carry no test references.
    let status = capability.status.as_deref();
    let testable = !matches!(status, Some("not-applicable") | Some("legacy-excluded"));
    if testable && capability.tests.is_empty() {
        violations.push(format!("{label}: tests must not be empty"));
    }
    for test in &capability.tests {
        if !is_test_id(test) {
            violations.push(format!(
                "{label}: test `{test}` must match ^(T|IT|E2E)-[0-9]+$"
            ));
        }
    }

    // PRD T-19: `verified` claims require evidence.
    if capability.status.as_deref() == Some("verified") {
        match capability.verified_at.as_deref().map(str::trim) {
            Some(verified_at) if !verified_at.is_empty() => {}
            _ => violations.push(format!(
                "{label}: verified capabilities must carry a non-empty `verified_at` (T-19)"
            )),
        }
        if capability.tests.is_empty() {
            violations.push(format!(
                "{label}: verified capabilities must reference at least one test (T-19)"
            ));
        }
        if capability.sources.is_empty() {
            violations.push(format!(
                "{label}: verified capabilities must reference at least one source (T-19)"
            ));
        }
    }

    if capability.status.as_deref() == Some("blocked-upstream") {
        match capability.blocker.as_deref().map(str::trim) {
            Some(blocker) if !blocker.is_empty() => {}
            _ => violations.push(format!(
                "{label}: blocked-upstream capabilities must carry a non-empty `blocker`"
            )),
        }
    }

    violations
}

fn status_counts(doc: &Manifest) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    if let Some(capabilities) = &doc.capabilities {
        for capability in capabilities {
            if let Some(status) = &capability.status {
                *counts.entry(status.clone()).or_insert(0) += 1;
            }
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A minimal lockfile fixture matching the good manifest's pins — the
    /// real Cargo.lock carries the same two checksums for muon 2.6.1 and
    /// pvpnclient 3.0.3 (Proton sparse-registry entries).
    fn good_lockfile_text() -> String {
        "\
version = 4

[[package]]
name = \"muon\"
version = \"2.6.1\"
source = \"sparse+https://rust-registry.proton.me/index/\"
checksum = \"be9ba1f347e00a86119ff6b70d36356cce28c33fd000290cc1254bf4048155de\"

[[package]]
name = \"pvpnclient\"
version = \"3.0.3\"
source = \"sparse+https://rust-registry.proton.me/index/\"
checksum = \"3c14ef052727e0204ec5e80cf8df50786db38a83b6a6557a188b78a4c264f380\"
"
        .to_string()
    }

    fn good_lock() -> Lockfile {
        Lockfile::parse(&good_lockfile_text()).unwrap()
    }

    fn good_manifest_yaml() -> String {
        "\
schema_version: 3
baseline:
  as_of: \"2026-01-01\"
client_contract:
  required_v1_clients: [cli, tui, gui]
upstream:
  protun:
    version: 2.2.1
    revision: 12e7755a112f59b7b843da79290b3de25febf653
  muon:
    version: 2.6.1
    checksum_sha256: be9ba1f347e00a86119ff6b70d36356cce28c33fd000290cc1254bf4048155de
  pvpnclient:
    version: 3.0.3
    checksum_sha256: 3c14ef052727e0204ec5e80cf8df50786db38a83b6a6557a188b78a4c264f380
  official_linux_cli:
    revision: a7c7abc8d3777f33b8d4c82279bd621258bd810d
  official_linux_gui:
    revision: bd9c406befad847d613ba3fc634b0f0ea9f1a72e
  official_linux_api_core:
    revision: fb35f610fc592ddc181230369dc59855c4f97a04
  official_android_app:
    revision: cc1e29f8acd5f11f63701b48f97410e90fa6a71d
  official_windows_app:
    revision: 4d9ac60d1db5d3f2908498470a9d1646723afcfd
  official_apple_app:
    revision: 6973fc1f7703314d80cada3eba377766c55710e5
status_definitions:
  required: r
  implemented: i
  verified: v
  blocked-upstream: b
  not-applicable: n
  legacy-excluded: l
sources:
  docs: https://example.com
capabilities:
  - id: account.login
    area: account
    status: required
    behavior: Log in.
    owner: protonwire-api
    sources: [docs]
    tests: [T-1]
  - id: legacy.openvpn
    area: legacy
    status: legacy-excluded
    behavior: Excluded.
    owner: none
    sources: [docs]
    tests: [T-2]
"
        .to_string()
    }

    fn temp_yaml(tag: &str, content: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("xtask-manifest-{tag}-{}", std::process::id()));
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn good_manifest_passes() {
        let path = temp_yaml("good", &good_manifest_yaml());
        assert!(
            validate(&path, &good_lock()).unwrap(),
            "expected the good fixture to pass"
        );
        fs::remove_file(&path).ok();
    }
    /// Codex PR review round 2, finding 6 (P2): the muon/pvpnclient
    /// checksums were only SHAPE-checked (64 lowercase hex characters), so
    /// replacing either recorded digest with any other well-formed value
    /// passed manifest-validate even when it disagreed with the pinned
    /// checksum in Cargo.lock — the resolution authority (PRD 6.5). The
    /// gate must compare the recorded digests against the lockfile.
    #[test]
    fn upstream_checksums_must_match_the_lockfile() {
        // A well-formed but wrong muon digest is tampering the shape check
        // cannot see (last hex digit flipped).
        let yaml = good_manifest_yaml().replacen(
            "be9ba1f347e00a86119ff6b70d36356cce28c33fd000290cc1254bf4048155de",
            "be9ba1f347e00a86119ff6b70d36356cce28c33fd000290cc1254bf4048155df",
            1,
        );
        let path = temp_yaml("checksum", &yaml);
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "a digest that disagrees with Cargo.lock must fail the gate"
        );
        fs::remove_file(&path).ok();

        // The untampered manifest agrees with the lockfile and passes.
        let path = temp_yaml("checksum-ok", &good_manifest_yaml());
        assert!(
            validate(&path, &good_lock()).unwrap(),
            "the matching fixture must still pass"
        );
        fs::remove_file(&path).ok();

        // A lockfile without the pinned package cannot verify the digest:
        // the gate must fail rather than pass vacuously.
        let empty = Lockfile::parse("version = 4\n").unwrap();
        let path = temp_yaml("checksum-empty", &good_manifest_yaml());
        assert!(
            !validate(&path, &empty).unwrap(),
            "an unverifiable checksum must fail, not pass vacuously"
        );
        fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_schema_version_fails() {
        let yaml = good_manifest_yaml().replacen("schema_version: 3", "schema_version: 2", 1);
        let path = temp_yaml("version", &yaml);
        assert!(!validate(&path, &good_lock()).unwrap());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn tampered_proton_pin_fails() {
        let yaml = good_manifest_yaml().replacen("revision: 12e7755a", "revision: not-th", 1);
        let path = temp_yaml("pin", &yaml);
        assert!(!validate(&path, &good_lock()).unwrap());
        fs::remove_file(&path).ok();
    }

    /// Codex PR review round 2, finding 5 (P2): status_definitions only
    /// had to CONTAIN the six frozen statuses — extra invented ones were
    /// allowed, and check_capabilities built its accepted set from all
    /// definition keys, so a `waived` status with capabilities assigned
    /// to it passed manifest-validate, drifting past the fixed parity
    /// vocabulary the gate claims to enforce.
    #[test]
    fn status_definitions_must_match_the_frozen_vocabulary_exactly() {
        // An extra definition alone is vocabulary drift...
        let yaml = good_manifest_yaml().replacen(
            "  legacy-excluded: l\n",
            "  legacy-excluded: l\n  waived: w\n",
            1,
        );
        let path = temp_yaml("extra-status", &yaml);
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "an extra status definition must fail the gate"
        );
        fs::remove_file(&path).ok();

        // ...and capabilities cannot flee to invented statuses either.
        let yaml = good_manifest_yaml()
            .replacen(
                "  legacy-excluded: l\n",
                "  legacy-excluded: l\n  waived: w\n",
                1,
            )
            .replacen("    status: required", "    status: waived", 1);
        let path = temp_yaml("waived-cap", &yaml);
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "a capability using an invented status must fail the gate"
        );
        fs::remove_file(&path).ok();
    }
    #[test]
    fn verified_without_evidence_fails() {
        let yaml = good_manifest_yaml().replacen(
            "  - id: legacy.openvpn",
            "  - id: account.magic\n    area: account\n    status: verified\n    behavior: Magic.\n    owner: protonwire-api\n    sources: [docs]\n    tests: [T-3]\n  - id: legacy.openvpn",
            1,
        );
        let path = temp_yaml("verified", &yaml);
        assert!(!validate(&path, &good_lock()).unwrap());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn blocked_upstream_without_blocker_fails() {
        let yaml = good_manifest_yaml().replacen(
            "  - id: legacy.openvpn",
            "  - id: account.hv\n    area: account\n    status: blocked-upstream\n    behavior: HV.\n    owner: protonwire-api\n    sources: [docs]\n    tests: [T-4]\n  - id: legacy.openvpn",
            1,
        );
        let path = temp_yaml("blocked", &yaml);
        assert!(!validate(&path, &good_lock()).unwrap());
        fs::remove_file(&path).ok();
    }

    fn cap(id: &str, area: &str, status: &str, owner: &str) -> Capability {
        Capability {
            id: Some(id.to_string()),
            area: Some(area.to_string()),
            status: Some(status.to_string()),
            behavior: Some("does something".to_string()),
            owner: Some(owner.to_string()),
            sources: vec!["docs".to_string()],
            tests: vec!["T-1".to_string()],
            verified_at: None,
            blocker: None,
        }
    }

    fn contexts() -> (BTreeSet<&'static str>, BTreeSet<&'static str>) {
        (
            REQUIRED_STATUSES.iter().copied().collect(),
            ["docs"].into_iter().collect(),
        )
    }

    #[test]
    fn area_must_be_known_vocabulary() {
        let (statuses, sources) = contexts();
        let violations = check_capability(
            0,
            &cap("account.login", "accounts", "required", "protonwire-api"),
            &statuses,
            &sources,
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("not one of the known areas"))
        );
        // The coarse-area design allows `protocol.smart` in area `protocols`.
        assert!(
            check_capability(
                0,
                &cap(
                    "protocol.smart",
                    "protocols",
                    "required",
                    "protonwire-protocol"
                ),
                &statuses,
                &sources,
            )
            .is_empty()
        );
    }

    #[test]
    fn owner_must_be_allowed() {
        let (statuses, sources) = contexts();
        let violations = check_capability(
            0,
            &cap("account.login", "account", "required", "someone"),
            &statuses,
            &sources,
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("not an allowed owner"))
        );
    }

    #[test]
    fn unknown_status_and_source_are_rejected() {
        let (statuses, sources) = contexts();
        let mut capability = cap("account.login", "account", "dreaming", "protonwire-api");
        capability.sources = vec!["nowhere".to_string()];
        let violations = check_capability(0, &capability, &statuses, &sources);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("not defined in status_definitions"))
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("not a top-level source key"))
        );
    }

    #[test]
    fn malformed_tests_are_rejected() {
        let (statuses, sources) = contexts();
        let mut capability = cap("account.login", "account", "required", "protonwire-api");
        capability.tests = vec!["T-1".to_string(), "unit-9".to_string()];
        let violations = check_capability(0, &capability, &statuses, &sources);
        assert!(violations.iter().any(|v| v.contains("unit-9")));
    }

    #[test]
    fn upstream_rules() {
        let mut upstream: BTreeMap<String, UpstreamEntry> = BTreeMap::new();
        upstream.insert(
            "protun".to_string(),
            UpstreamEntry {
                version: Some("2.2.1".to_string()),
                revision: Some(PROTON_REVISION.to_string()),
                checksum_sha256: None,
            },
        );
        upstream.insert(
            "muon".to_string(),
            UpstreamEntry {
                version: Some("2.6.1".to_string()),
                revision: None,
                checksum_sha256: Some(
                    "be9ba1f347e00a86119ff6b70d36356cce28c33fd000290cc1254bf4048155de".to_string(),
                ),
            },
        );
        upstream.insert(
            "pvpnclient".to_string(),
            UpstreamEntry {
                version: Some("3.0.3".to_string()),
                revision: None,
                checksum_sha256: Some(
                    "3c14ef052727e0204ec5e80cf8df50786db38a83b6a6557a188b78a4c264f380".to_string(),
                ),
            },
        );
        upstream.insert(
            "official_linux_cli".to_string(),
            UpstreamEntry {
                version: None,
                revision: Some("a7c7abc8d3777f33b8d4c82279bd621258bd810d".to_string()),
                checksum_sha256: None,
            },
        );
        for (name, revision) in [
            (
                "official_linux_gui",
                "bd9c406befad847d613ba3fc634b0f0ea9f1a72e",
            ),
            (
                "official_linux_api_core",
                "fb35f610fc592ddc181230369dc59855c4f97a04",
            ),
            (
                "official_android_app",
                "cc1e29f8acd5f11f63701b48f97410e90fa6a71d",
            ),
            (
                "official_windows_app",
                "4d9ac60d1db5d3f2908498470a9d1646723afcfd",
            ),
            (
                "official_apple_app",
                "6973fc1f7703314d80cada3eba377766c55710e5",
            ),
        ] {
            upstream.insert(
                name.to_string(),
                UpstreamEntry {
                    version: None,
                    revision: Some(revision.to_string()),
                    checksum_sha256: None,
                },
            );
        }
        let mut doc = Manifest {
            schema_version: Some(3),
            baseline: None,
            client_contract: None,
            upstream: Some(upstream),
            status_definitions: None,
            sources: None,
            capabilities: None,
        };
        assert!(check_upstream(&doc, &good_lock()).is_empty());

        if let Some(upstream) = doc.upstream.as_mut() {
            upstream.get_mut("official_linux_cli").unwrap().revision = Some("short".to_string());
        }
        assert!(
            check_upstream(&doc, &good_lock())
                .iter()
                .any(|v| v.contains("official_linux_cli"))
        );
    }
}
