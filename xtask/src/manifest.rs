//! `cargo xtask manifest-validate` — validates `docs/official-parity.yaml`
//! (schema version 3) against the parity-manifest contract.
//!
//! Enforces the pinned upstream revisions/checksums, the status vocabulary,
//! the typed non-empty source references, capability id/area/owner/source/
//! test invariants, and the T-19 evidence rule (`verified` capabilities
//! must carry `verified_at`, tests, and sources).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

use crate::{
    Reporter, expect_value, is_capability_id, is_git_revision, is_sha256_hex, is_test_id, set_drift,
};

const PROTON_REVISION: &str = "12e7755a112f59b7b843da79290b3de25febf653";

/// The six pinned official-client baselines (upstream name → recorded git
/// revision from docs/official-parity.yaml), in the EXPECTED_GROUP_IDS pin
/// style: the revisions are pinned constants in the gate rather than values
/// read back out of the validated document (self-consistency would let an
/// edited docs file vouch for itself), so a swapped-but-valid revision is
/// drift the gate catches and a real baseline bump is a deliberate
/// docs-plus-xtask change.
const OFFICIAL_REVISIONS: &[(&str, &str)] = &[
    (
        "official_linux_cli",
        "a7c7abc8d3777f33b8d4c82279bd621258bd810d",
    ),
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
];

const REQUIRED_STATUSES: &[&str] = &[
    "required",
    "implemented",
    "verified",
    "blocked-upstream",
    "not-applicable",
    "legacy-excluded",
];

const EXPECTED_CAPABILITY_COUNT: usize = 72;

/// The canonical capability id set (docs/official-parity.yaml), pinned the
/// EXPECTED_GROUP_IDS way: set equality, not per-entry membership. The
/// per-entry checks alone let a DELETED capability pass — every surviving
/// entry stays individually valid while the parity contract silently
/// shrinks — and an invented id is equally invisible. Recording the set in
/// the gate (rather than reading it back out of the validated document)
/// makes adding or removing a capability a deliberate docs-plus-xtask
/// change.
const EXPECTED_CAPABILITY_IDS: [&str; EXPECTED_CAPABILITY_COUNT] = [
    "account.login",
    "account.session",
    "account.credential-lifecycle",
    "account.two-factor",
    "account.human-verification",
    "account.sso",
    "account.guest-mode",
    "account.entitlements-and-jails",
    "security.upstream-secret-logging",
    "protocol.smart",
    "protocol.wireguard-udp",
    "protocol.wireguard-tcp",
    "protocol.stealth",
    "protocol.network-change",
    "protocol.circumvention-routing",
    "servers.catalog-and-search",
    "servers.metadata-refresh-budget",
    "servers.fastest-and-random",
    "groups.official-built-ins",
    "groups.fastest-excluding-my-country",
    "groups.anti-censorship",
    "groups.regional-fastest",
    "groups.cross-client-parity",
    "servers.location",
    "servers.exact",
    "servers.free-change",
    "servers.secure-core",
    "servers.p2p",
    "servers.tor",
    "servers.streaming",
    "servers.gateway",
    "profiles.crud-and-types",
    "profiles.overrides",
    "profiles.recents-pins-default",
    "profiles.connect-and-go",
    "profiles.import-export",
    "protection.kill-switch-standard",
    "protection.kill-switch-permanent",
    "protection.dns-and-ipv6-leaks",
    "protection.lan",
    "protection.lan-name-resolution",
    "protection.auto-connect-reconnect",
    "dns.proton-and-custom",
    "dns.netshield-levels",
    "dns.netshield-statistics",
    "options.vpn-accelerator",
    "options.nat",
    "options.port-forwarding",
    "options.ipv6-and-mtu",
    "split.apps-and-ip",
    "split.advanced-linux-policy",
    "split.domains",
    "split.kill-switch-coexistence",
    "diagnostics.connection-details",
    "diagnostics.packet-capture",
    "diagnostics.debug-and-crash",
    "diagnostics.network-conflict-detection",
    "diagnostics.connection-feedback",
    "clients.single-core-monorepo",
    "clients.shared-sdk",
    "clients.cli",
    "clients.ratatui-tui",
    "clients.tauri-gui",
    "clients.cross-client-parity",
    "integration.native",
    "integration.network-manager",
    "integration.systemd-networkd",
    "integration.headless-frontend-api",
    "integration.nixos",
    "legacy.openvpn",
    "legacy.ikev2",
    "presentation.mobile-tv-browser-ui",
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

const CANONICAL_TEST_COUNT: usize = 92;

/// The canonical test inventory (docs/PRD-proton-wire.md sections
/// 17.1-17.3): 37 unit (T-*), 30 integration (IT-*), and 25 end-to-end
/// (E2E-*) ids, extracted from the PRD once and recorded here — the same
/// pin family as EXPECTED_CAPABILITY_IDS. Every `tests:` reference in the
/// parity manifest must resolve against this inventory; parsing the PRD
/// at runtime instead would hang the gate on the very document class it
/// defends (round-6 triage note: fragile), while a recorded baseline
/// turns a new test id into a deliberate PRD-plus-xtask change.
const CANONICAL_TEST_IDS: [&str; CANONICAL_TEST_COUNT] = [
    "T-1", "T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9", "T-10", "T-11", "T-12", "T-13",
    "T-14", "T-15", "T-16", "T-17", "T-18", "T-19", "T-20", "T-21", "T-22", "T-23", "T-24", "T-25",
    "T-26", "T-27", "T-28", "T-29", "T-30", "T-31", "T-32", "T-33", "T-34", "T-35", "T-36", "T-37",
    "IT-1", "IT-2", "IT-3", "IT-4", "IT-5", "IT-6", "IT-7", "IT-8", "IT-9", "IT-10", "IT-11",
    "IT-12", "IT-13", "IT-14", "IT-15", "IT-16", "IT-17", "IT-18", "IT-19", "IT-20", "IT-21",
    "IT-22", "IT-23", "IT-24", "IT-25", "IT-26", "IT-27", "IT-28", "IT-29", "IT-30", "E2E-1",
    "E2E-2", "E2E-3", "E2E-4", "E2E-5", "E2E-6", "E2E-7", "E2E-8", "E2E-9", "E2E-10", "E2E-11",
    "E2E-12", "E2E-13", "E2E-14", "E2E-15", "E2E-16", "E2E-17", "E2E-18", "E2E-19", "E2E-20",
    "E2E-21", "E2E-22", "E2E-23", "E2E-24", "E2E-25",
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
    reporter.rule("source reference entries", &check_sources(&doc));
    reporter.rule("upstream pins", &check_upstream(&doc, lock));
    reporter.rule("canonical capability id set", &check_capability_ids(&doc));
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

/// The JSON kind of a malformed source entry, for violation wording.
fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// Round-8 X3: the top-level `sources` map's values were arbitrary JSON
/// with only the KEYS checked — capabilities cite the keys as evidence
/// references, so a null, empty, or non-string value passed while every
/// capability citing it pointed at evidence that is not a reference at
/// all. Every entry must be a defined, non-empty string; each violation
/// names the key and the defect kind.
fn check_sources(doc: &Manifest) -> Vec<String> {
    let Some(sources) = &doc.sources else {
        // The required-top-level-keys rule already reports the missing map.
        return Vec::new();
    };
    let mut violations = Vec::new();
    for (key, value) in sources {
        match value {
            serde_json::Value::String(text) if !text.trim().is_empty() => {}
            serde_json::Value::String(_) => violations.push(format!(
                "source `{key}` must be a non-empty string, got an empty string"
            )),
            other => violations.push(format!(
                "source `{key}` must be a non-empty string, got {}",
                json_kind(other)
            )),
        }
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

/// Round-8 X6: like the checksum rule above, the recorded ProTUN revision
/// is compared against the resolution authority — the git revision
/// Cargo.lock actually locked for the package (the `git+…#<rev>` source
/// fragment) — and not only against the validator constant, so the pin
/// cannot drift from the resolved dependency silently. A lockfile entry
/// without a git revision fails rather than passing vacuously.
fn expect_lock_revision(recorded: Option<&str>, locked: Option<&str>, what: &str) -> Vec<String> {
    match (recorded, locked) {
        (Some(recorded), Some(locked)) if recorded == locked => Vec::new(),
        (Some(recorded), Some(locked)) => vec![format!(
            "{what} `{recorded}` disagrees with the Cargo.lock git revision `{locked}`"
        )],
        (Some(_), None) => vec![format!(
            "{what} cannot be verified: Cargo.lock records no git revision for the pinned version"
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
    /// `(name, version)` → resolved git revision, for packages whose
    /// source is a git dependency (`git+…#<rev>`; round-8 X6).
    git_revs: BTreeMap<(String, String), String>,
}

#[derive(Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
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
    ///
    /// Duplicate `(name, version)` entries are a hard error (sec-auditor,
    /// consolidated round 3, item I): the checksum lookups key on that
    /// pair, and two sources resolving the same pair make "the" checksum
    /// whichever entry the collector saw last — an ambiguity the digest
    /// comparison cannot detect. Rejecting forces a human to reconcile
    /// the lockfile instead of the gate guessing.
    fn parse(text: &str) -> Result<Self> {
        let doc: LockDocument =
            toml::from_str(text).with_context(|| "failed to parse Cargo.lock")?;
        let mut checksums = BTreeMap::new();
        let mut git_revs = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for package in doc.packages {
            let key = (package.name.clone(), package.version.clone());
            if !seen.insert(key.clone()) {
                return Err(anyhow!(
                    "Cargo.lock lists {} {} more than once — duplicate \
                     (name, version) entries make the checksum ambiguous",
                    package.name,
                    package.version,
                ));
            }
            if let Some(checksum) = package.checksum {
                checksums.insert(key.clone(), checksum);
            }
            // Round-8 X6: git dependencies record the commit Cargo
            // actually resolved as the `#<rev>` fragment of their
            // `git+…` source URL.
            if let Some(rev) = package.source.as_deref().and_then(git_rev_from_source) {
                git_revs.insert(key, rev.to_owned());
            }
        }
        Ok(Self {
            checksums,
            git_revs,
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

    /// The git revision Cargo resolved for `name` at `version`, if the
    /// lockfile entry is a git dependency carrying one (round-8 X6).
    fn git_rev(&self, name: &str, version: &str) -> Option<&str> {
        self.git_revs
            .get(&(name.to_owned(), version.to_owned()))
            .map(String::as_str)
    }
}

/// The commit a git dependency locked to. Cargo records git sources as
/// `git+<url>?rev=<rev>#<rev>` (and branch/tag pins as
/// `git+<url>?branch=…#<rev>`): the `#` fragment is always the commit
/// actually checked out — the query parameters only record what was
/// requested — so the fragment is the resolved revision.
fn git_rev_from_source(source: &str) -> Option<&str> {
    let url = source.strip_prefix("git+")?;
    let (_, rev) = url.rsplit_once('#')?;
    (!rev.is_empty()).then_some(rev)
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
            // Round-8 X6: the constant pin alone cannot see the manifest
            // drifting from what Cargo actually resolved.
            violations.extend(expect_lock_revision(
                entry.revision.as_deref(),
                lock.git_rev("protun", "2.2.1"),
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

    for (name, pinned) in OFFICIAL_REVISIONS {
        match upstream.get(*name) {
            Some(entry) => {
                violations.extend(expect_revision(
                    entry.revision.as_deref(),
                    &format!("upstream.{name}"),
                ));
                // WO-W4: the shape check alone lets any well-formed hash
                // through; the recorded revision must EQUAL the pin.
                violations.extend(expect_value(
                    entry.revision.as_deref(),
                    pinned,
                    &format!("upstream.{name}.revision"),
                ));
            }
            None => violations.push(format!("upstream.{name} is missing")),
        }
    }

    // Any further upstream entry must also record a full git revision.
    for (name, entry) in upstream {
        if matches!(name.as_str(), "protun" | "muon" | "pvpnclient")
            || OFFICIAL_REVISIONS
                .iter()
                .any(|(official, _)| *official == name.as_str())
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

/// WO-W5 (pr-champion round-6): set equality against the canonical
/// capability id set. The per-entry checks alone let a DELETED capability
/// pass — every surviving entry stays individually valid while the parity
/// contract silently shrinks — and an invented id is equally invisible to
/// them. Each violation names the drifted id so the gate output points at
/// the exact contract change.
fn check_capability_ids(doc: &Manifest) -> Vec<String> {
    let Some(capabilities) = &doc.capabilities else {
        // The `capabilities` rule already reports the missing list; 72
        // "missing id" lines on top would only bury that signal.
        return Vec::new();
    };
    let actual: BTreeSet<&str> = capabilities
        .iter()
        .filter_map(|c| c.id.as_deref())
        .collect();
    let (missing, invented) = set_drift(&EXPECTED_CAPABILITY_IDS, &actual);
    let mut violations = Vec::new();
    for id in missing {
        violations.push(format!("canonical capability `{id}` is missing"));
    }
    for id in invented {
        violations.push(format!(
            "capability `{id}` is not part of the canonical id set"
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
    // WO-W6: the recorded PRD section-17 inventory every tests reference
    // must resolve against.
    let test_ids: BTreeSet<&str> = CANONICAL_TEST_IDS.iter().copied().collect();

    let mut seen = BTreeSet::new();
    for (index, capability) in capabilities.iter().enumerate() {
        if let Some(id) = &capability.id
            && !seen.insert(id.clone())
        {
            violations.push(format!("duplicate capability id `{id}`"));
        }
        violations.extend(check_capability(
            index, capability, &statuses, &sources, &test_ids,
        ));
    }
    violations
}

fn check_capability(
    index: usize,
    capability: &Capability,
    statuses: &BTreeSet<&str>,
    sources: &BTreeSet<&str>,
    test_ids: &BTreeSet<&str>,
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
        } else if !test_ids.contains(test.as_str()) {
            // WO-W6: a well-formed id that matches no PRD test is
            // evidence pointing at nothing.
            violations.push(format!(
                "{label}: test `{test}` is not in the canonical PRD test inventory"
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
    /// pvpnclient 3.0.3 (Proton sparse-registry entries) and the same git
    /// source for protun 2.2.1 (`git+…?rev=…#…`, the fragment being the
    /// commit Cargo actually resolved).
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

[[package]]
name = \"protun\"
version = \"2.2.1\"
source = \"git+https://github.com/ProtonVPN/protun?rev=12e7755a112f59b7b843da79290b3de25febf653#12e7755a112f59b7b843da79290b3de25febf653\"
"
        .to_string()
    }

    fn good_lock() -> Lockfile {
        Lockfile::parse(&good_lockfile_text()).unwrap()
    }

    /// A manifest fixture whose capability list is exactly `ids` (each a
    /// uniform per-entry-valid record): the good fixture must enumerate
    /// the full canonical set because the id SET is what the gate pins,
    /// and the drift tests derive their fixtures by dropping or adding
    /// ids here.
    fn manifest_yaml_with_ids(ids: &[&str]) -> String {
        let mut yaml = "\
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
"
        .to_string();
        for id in ids {
            yaml.push_str(&format!(
                "  - id: {id}\n    area: account\n    status: required\n    behavior: Does something.\n    owner: protonwire-api\n    sources: [docs]\n    tests: [T-1]\n"
            ));
        }
        yaml
    }

    fn good_manifest_yaml() -> String {
        manifest_yaml_with_ids(&EXPECTED_CAPABILITY_IDS)
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

    /// pr-champion round-6 triage, WO-W5: capabilities were checked only
    /// per-entry, so DELETING one (e.g. account.login) left every
    /// surviving entry valid and the gate green — the parity contract
    /// silently shrinking. The canonical id set is pinned and enforced as
    /// set equality: a missing id and an invented id are both violations.
    #[test]
    fn deleted_or_invented_capability_ids_fail() {
        // Dropping account.login: every surviving entry is individually
        // valid; only the set pin can notice the contract shrank.
        let without: Vec<&str> = EXPECTED_CAPABILITY_IDS
            .iter()
            .copied()
            .filter(|id| *id != "account.login")
            .collect();
        let path = temp_yaml("missing-cap", &manifest_yaml_with_ids(&without));
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "a manifest missing account.login must fail the gate"
        );
        fs::remove_file(&path).ok();

        // The violation must NAME the missing id, not just count it.
        let doc: Manifest = serde_norway::from_str(&manifest_yaml_with_ids(&without)).unwrap();
        assert!(
            check_capability_ids(&doc)
                .iter()
                .any(|v| v == "canonical capability `account.login` is missing"),
            "the id-set violation must name `account.login`"
        );

        // Adding a well-formed id the canonical set never contained.
        let mut with_extra = EXPECTED_CAPABILITY_IDS.to_vec();
        with_extra.push("account.magic");
        let path = temp_yaml("extra-cap", &manifest_yaml_with_ids(&with_extra));
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "an invented capability id must fail the gate"
        );
        fs::remove_file(&path).ok();

        // The extra id is named too.
        let doc: Manifest = serde_norway::from_str(&manifest_yaml_with_ids(&with_extra)).unwrap();
        assert!(
            check_capability_ids(&doc)
                .iter()
                .any(|v| v == "capability `account.magic` is not part of the canonical id set"),
            "the id-set violation must name `account.magic`"
        );
    }

    /// The pin itself is pinned (the canonical_ids meta-test style): a
    /// stray edit to the constant — typo, duplicate, count change — must
    /// fail loudly instead of quietly redefining the contract.
    #[test]
    fn canonical_capability_id_set_is_pinned() {
        for id in EXPECTED_CAPABILITY_IDS {
            assert!(is_capability_id(id), "`{id}` must match the id shape");
        }
        let unique: BTreeSet<&str> = EXPECTED_CAPABILITY_IDS.iter().copied().collect();
        assert_eq!(
            unique.len(),
            EXPECTED_CAPABILITY_COUNT,
            "the pinned id set must contain exactly {EXPECTED_CAPABILITY_COUNT} unique ids"
        );
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

        // QA mutation gap (item G5): the symmetric tamper on the pvpnclient
        // digest — the muon case passing does not prove this branch.
        let yaml = good_manifest_yaml().replacen(
            "3c14ef052727e0204ec5e80cf8df50786db38a83b6a6557a188b78a4c264f380",
            "3c14ef052727e0204ec5e80cf8df50786db38a83b6a6557a188b78a4c264f381",
            1,
        );
        let path = temp_yaml("checksum-pvpn", &yaml);
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "a tampered pvpnclient digest must fail the gate too, not just muon's"
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

    /// Round-8 X6: the ProTUN revision was compared only against the
    /// PROTON_REVISION constant, so the manifest pin could drift from the
    /// revision Cargo actually resolved — recorded in Cargo.lock as the
    /// `git+…#<rev>` source fragment — with nothing comparing the two.
    /// The pin must be cross-checked against the lockfile (the same
    /// resolution authority the checksum rule uses), naming both values
    /// on disagreement.
    #[test]
    fn protun_revision_must_match_the_lockfile_git_rev() {
        // The lockfile resolved a DIFFERENT commit than the manifest pins
        // (both well-formed, the manifest still equal to the constant
        // pin): only the lockfile cross-check can see the disagreement.
        let tampered = good_lockfile_text().replacen(
            "12e7755a112f59b7b843da79290b3de25febf653",
            "12e7755a112f59b7b843da79290b3de25febf654",
            2,
        );
        let path = temp_yaml("protun-lock", &good_manifest_yaml());
        assert!(
            !validate(&path, &Lockfile::parse(&tampered).unwrap()).unwrap(),
            "a manifest pin disagreeing with the resolved Cargo.lock revision must fail the gate"
        );
        fs::remove_file(&path).ok();

        // A lockfile without a protun git entry cannot verify the pin:
        // the gate must fail rather than pass vacuously.
        let path = temp_yaml("protun-absent", &good_manifest_yaml());
        assert!(
            !validate(&path, &Lockfile::parse("version = 4\n").unwrap()).unwrap(),
            "an unverifiable protun pin must fail, not pass vacuously"
        );
        fs::remove_file(&path).ok();

        // The fixture agreeing with the lockfile still passes.
        let path = temp_yaml("protun-ok", &good_manifest_yaml());
        assert!(
            validate(&path, &good_lock()).unwrap(),
            "the fixture agreeing with the lockfile must pass"
        );
        fs::remove_file(&path).ok();

        // The mismatch violation must NAME both revisions.
        let doc: Manifest = serde_norway::from_str(&good_manifest_yaml()).unwrap();
        assert!(
            check_upstream(&doc, &Lockfile::parse(&tampered).unwrap())
                .iter()
                .any(|v| v.contains("12e7755a112f59b7b843da79290b3de25febf653")
                    && v.contains("12e7755a112f59b7b843da79290b3de25febf654")),
            "the violation must name the recorded pin and the resolved revision"
        );
    }

    /// pr-champion round-6 triage, WO-W4: the six official-client baselines
    /// were only SHAPE-checked (40 hex characters), so replacing any
    /// recorded revision with a different well-formed hash passed
    /// manifest-validate — silent baseline drift the shape rule cannot
    /// see, exactly like the checksum finding above. Each revision is
    /// pinned instead (the EXPECTED_GROUP_IDS style): changing one must be
    /// a deliberate docs-plus-xtask edit, never a one-file accident.
    #[test]
    fn official_revisions_must_match_the_pinned_baselines() {
        // A swapped-but-valid revision (last hex digit flipped) on the
        // first baseline.
        let yaml = good_manifest_yaml().replacen(
            "a7c7abc8d3777f33b8d4c82279bd621258bd810d",
            "a7c7abc8d3777f33b8d4c82279bd621258bd810e",
            1,
        );
        let path = temp_yaml("official-rev", &yaml);
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "a swapped-but-valid official_linux_cli revision must fail the gate"
        );
        fs::remove_file(&path).ok();

        // The same tamper on the LAST baseline proves the loop covers
        // every official entry, not just the first.
        let yaml = good_manifest_yaml().replacen(
            "6973fc1f7703314d80cada3eba377766c55710e5",
            "6973fc1f7703314d80cada3eba377766c55710f",
            1,
        );
        let path = temp_yaml("official-rev-last", &yaml);
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "a swapped-but-valid official_apple_app revision must fail the gate too"
        );
        fs::remove_file(&path).ok();

        // Exchanging two official revisions (both well-formed, each in the
        // wrong slot) must fail on both entries; the keyed search strings
        // keep each `replacen` pinned to its own upstream block.
        let yaml = good_manifest_yaml()
            .replacen(
                "official_linux_cli:\n    revision: a7c7abc8d3777f33b8d4c82279bd621258bd810d",
                "official_linux_cli:\n    revision: bd9c406befad847d613ba3fc634b0f0ea9f1a72e",
                1,
            )
            .replacen(
                "official_linux_gui:\n    revision: bd9c406befad847d613ba3fc634b0f0ea9f1a72e",
                "official_linux_gui:\n    revision: a7c7abc8d3777f33b8d4c82279bd621258bd810d",
                1,
            );
        let path = temp_yaml("official-rev-swap", &yaml);
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "two official revisions exchanged between their slots must fail the gate"
        );
        fs::remove_file(&path).ok();
    }

    /// Sec-auditor (consolidated round 3, item I): the parsed lockfile map
    /// keyed (name, version) silently OVERWROTE duplicates, so a lockfile
    /// carrying two entries for the same package+version (different
    /// sources) would resolve "the" checksum to whichever landed last —
    /// a supply-chain ambiguity the digest comparison cannot see. Parsing
    /// must reject duplicate (name, version) entries outright.
    #[test]
    fn duplicate_lock_entries_are_rejected_at_parse() {
        // The same package+version twice (a second source, no checksum):
        // indistinguishable from the real entry by the map key alone.
        let duplicated = format!(
            "{}\n[[package]]\nname = \"muon\"\nversion = \"2.6.1\"\nsource = \"git+https://example.com/muon?rev=deadbeef\"\n",
            good_lockfile_text()
        );
        let outcome = Lockfile::parse(&duplicated);
        assert!(
            outcome.is_err(),
            "a duplicate (name, version) lockfile entry must fail the parse, \
             not silently overwrite the checksum the gate compares against"
        );
        // The fixture without the duplicate still parses.
        assert!(Lockfile::parse(&good_lockfile_text()).is_ok());
    }

    #[test]
    fn wrong_schema_version_fails() {
        let yaml = good_manifest_yaml().replacen("schema_version: 3", "schema_version: 2", 1);
        let path = temp_yaml("version", &yaml);
        assert!(!validate(&path, &good_lock()).unwrap());
        fs::remove_file(&path).ok();
    }

    /// Round-8 X3: top-level source VALUES were never checked — `sources`
    /// deserialized as arbitrary JSON and only its KEYS were consulted
    /// (capability source membership), so a null, empty, or non-string
    /// entry passed while every capability citing it pointed its evidence
    /// at something that is not a reference at all. Each defect kind must
    /// fail the gate, naming the key and the defect.
    #[test]
    fn source_entries_must_be_non_empty_strings() {
        // Null.
        let yaml = good_manifest_yaml().replacen("  docs: https://example.com", "  docs: ~", 1);
        let path = temp_yaml("source-null", &yaml);
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "a null source value must fail the gate"
        );
        fs::remove_file(&path).ok();

        // Empty string.
        let yaml = good_manifest_yaml().replacen("  docs: https://example.com", "  docs: \"\"", 1);
        let path = temp_yaml("source-empty", &yaml);
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "an empty source value must fail the gate"
        );
        fs::remove_file(&path).ok();

        // Non-string (a number).
        let yaml = good_manifest_yaml().replacen("  docs: https://example.com", "  docs: 42", 1);
        let path = temp_yaml("source-number", &yaml);
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "a non-string source value must fail the gate"
        );
        fs::remove_file(&path).ok();

        // Each violation must NAME the key and the defect kind.
        for (yaml, defect) in [
            (
                good_manifest_yaml().replacen("  docs: https://example.com", "  docs: ~", 1),
                "null",
            ),
            (
                good_manifest_yaml().replacen("  docs: https://example.com", "  docs: \"\"", 1),
                "an empty string",
            ),
            (
                good_manifest_yaml().replacen("  docs: https://example.com", "  docs: 42", 1),
                "a number",
            ),
        ] {
            let doc: Manifest = serde_norway::from_str(&yaml).unwrap();
            assert!(
                check_sources(&doc)
                    .iter()
                    .any(|v| v.contains("`docs`") && v.contains(defect)),
                "the violation must name `docs` and the defect `{defect}`"
            );
        }

        // The untampered fixture still passes.
        let path = temp_yaml("source-ok", &good_manifest_yaml());
        assert!(
            validate(&path, &good_lock()).unwrap(),
            "the well-formed fixture must still pass"
        );
        fs::remove_file(&path).ok();
    }

    /// pr-champion round-6 triage, WO-W6: `tests:` references were only
    /// SHAPE-checked (^(T|IT|E2E)-[0-9]+$), so a well-formed id matching
    /// no PRD test — T-999999 — passed the gate while pointing its
    /// evidence at a test that does not exist. Every reference must
    /// resolve against the canonical PRD section-17 inventory.
    #[test]
    fn test_references_must_resolve_against_the_canonical_inventory() {
        let yaml = good_manifest_yaml().replacen("tests: [T-1]", "tests: [T-999999]", 1);
        let path = temp_yaml("phantom-test", &yaml);
        assert!(
            !validate(&path, &good_lock()).unwrap(),
            "a tests reference to T-999999 must fail the gate"
        );
        fs::remove_file(&path).ok();

        // The violation must NAME the phantom id.
        let (statuses, sources, test_ids) = contexts();
        let mut capability = cap("account.login", "account", "required", "protonwire-api");
        capability.tests = vec!["T-999999".to_string()];
        assert!(
            check_capability(0, &capability, &statuses, &sources, &test_ids)
                .iter()
                .any(|v| v.contains("T-999999") && v.contains("canonical PRD test inventory")),
            "the violation must name T-999999 as outside the inventory"
        );
    }

    /// The inventory itself is pinned (the canonical_capability meta-test
    /// style): 92 unique shape-valid ids with the PRD's exact 37/30/25
    /// split, so a stray edit to the constant fails loudly.
    #[test]
    fn canonical_test_inventory_is_pinned() {
        for id in CANONICAL_TEST_IDS {
            assert!(is_test_id(id), "`{id}` must match the test-id shape");
        }
        let unique: BTreeSet<&str> = CANONICAL_TEST_IDS.iter().copied().collect();
        assert_eq!(
            unique.len(),
            CANONICAL_TEST_COUNT,
            "the inventory must contain exactly {CANONICAL_TEST_COUNT} unique ids"
        );
        let count = |prefix: &str| {
            CANONICAL_TEST_IDS
                .iter()
                .filter(|id| id.starts_with(prefix))
                .count()
        };
        assert_eq!(count("T-"), 37, "PRD 17.1 defines 37 unit tests");
        assert_eq!(count("IT-"), 30, "PRD 17.2 defines 30 integration tests");
        assert_eq!(count("E2E-"), 25, "PRD 17.3 defines 25 end-to-end tests");
        // FU-D (round-6 verdict residual): counts alone do not pin WHICH
        // ids a prefix holds — swapping an unreferenced id for a phantom
        // (T-37 → T-99) keeps every count intact. Pin the max id per
        // prefix and require contiguity from 1, so both the phantom and
        // the hole it leaves are named drift in one failure.
        let mut drift = Vec::new();
        for (prefix, expected_max) in [("T-", 37u32), ("IT-", 30), ("E2E-", 25)] {
            let numbers: BTreeSet<u32> = CANONICAL_TEST_IDS
                .iter()
                .filter_map(|id| id.strip_prefix(prefix))
                .filter_map(|suffix| suffix.parse().ok())
                .collect();
            match numbers.iter().max() {
                Some(&max) if max == expected_max => {}
                other => drift.push(format!(
                    "{prefix} max id is {other:?}, expected {expected_max}"
                )),
            }
            for n in 1..=expected_max {
                if !numbers.contains(&n) {
                    drift.push(format!(
                        "`{prefix}{n}` is missing; {prefix} ids must be contiguous 1..={expected_max}"
                    ));
                }
            }
        }
        assert!(drift.is_empty(), "canonical inventory drift: {drift:?}");
    }

    /// Slices the PRD text between the (unique) `## 17.` Test Plan and
    /// `## 18.` Implementation Milestones headings — sections 17.1-17.3.
    fn test_plan_section(prd: &str) -> &str {
        let start = prd
            .find("## 17. Test Plan")
            .expect("the PRD must contain the `## 17. Test Plan` heading");
        let end = prd[start..]
            .find("## 18. Implementation Milestones")
            .map(|offset| start + offset)
            .expect("the PRD must contain the `## 18.` heading after the Test Plan");
        &prd[start..end]
    }

    /// Extracts the bold test ids from the sliced Test Plan text. Every
    /// PRD test entry opens its own line with exactly this shape
    /// (`**T-37:** Validate ...`, `**IT-30:** ...`, `**E2E-25:** ...`), so
    /// scanning line-initial `**` + id + `:**` prefixes matches the ids
    /// and nothing else in the section.
    fn bold_test_ids(section: &str) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        for line in section.lines() {
            let Some(rest) = line.trim_start().strip_prefix("**") else {
                continue;
            };
            let (prefix, tail) = if let Some(tail) = rest.strip_prefix("E2E-") {
                ("E2E-", tail)
            } else if let Some(tail) = rest.strip_prefix("IT-") {
                ("IT-", tail)
            } else if let Some(tail) = rest.strip_prefix("T-") {
                ("T-", tail)
            } else {
                continue;
            };
            let digits_end = tail
                .char_indices()
                .find(|(_, c)| !c.is_ascii_digit())
                .map(|(i, _)| i)
                .unwrap_or(tail.len());
            if digits_end > 0 && tail[digits_end..].starts_with(":**") {
                ids.insert(format!("{prefix}{}", &tail[..digits_end]));
            }
        }
        ids
    }

    /// FU-D (round-6 verdict residual): nine inventory ids (E2E-9, E2E-11,
    /// IT-1, IT-2, IT-13, IT-25, T-19, T-36, T-37) are referenced by no
    /// capability, so swapping any of them for a shape-valid phantom passed
    /// EVERYWHERE — the per-reference checks never fire on unreferenced
    /// ids, and the count companions alone cannot see a within-prefix
    /// swap. The constant cannot vouch for itself, so this test
    /// cross-checks it against the authoritative source it records:
    /// the PRD's own section 17.1-17.3 inventory.
    ///
    /// TEST-ONLY BY DESIGN — the GATE stays PRD-independent: `run`,
    /// `validate`, and every `check_*` never read the PRD (a missing or
    /// restructured PRD must never break `cargo xtask` itself), and the
    /// inventory constant remains the gate's single authority. Only this
    /// `#[cfg(test)]` code opens the PRD, so a PRD edit that forgets the
    /// constant (or vice versa) fails `cargo test`, not CI's real-docs
    /// run.
    #[test]
    fn canonical_test_inventory_matches_the_prd() {
        let prd = crate::workspace_root()
            .expect("cannot derive the workspace root")
            .join("docs")
            .join("PRD-proton-wire.md");
        let text = fs::read_to_string(&prd)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", prd.display()));
        let prd_ids = bold_test_ids(test_plan_section(&text));
        assert_eq!(
            prd_ids.len(),
            92,
            "PRD 17.1-17.3 must define 92 bold test ids (37 + 30 + 25)"
        );
        let pinned: BTreeSet<String> = CANONICAL_TEST_IDS
            .iter()
            .map(|id| String::from(*id))
            .collect();
        let not_pinned: Vec<&String> = prd_ids.difference(&pinned).collect();
        let not_in_prd: Vec<&String> = pinned.difference(&prd_ids).collect();
        assert!(
            not_pinned.is_empty() && not_in_prd.is_empty(),
            "CANONICAL_TEST_IDS drifted from the PRD 17.1-17.3 inventory — \
             in the PRD but not pinned: {not_pinned:?}; \
             pinned but not in the PRD: {not_in_prd:?}"
        );
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

    fn contexts() -> (
        BTreeSet<&'static str>,
        BTreeSet<&'static str>,
        BTreeSet<&'static str>,
    ) {
        (
            REQUIRED_STATUSES.iter().copied().collect(),
            ["docs"].into_iter().collect(),
            CANONICAL_TEST_IDS.iter().copied().collect(),
        )
    }

    #[test]
    fn area_must_be_known_vocabulary() {
        let (statuses, sources, test_ids) = contexts();
        let violations = check_capability(
            0,
            &cap("account.login", "accounts", "required", "protonwire-api"),
            &statuses,
            &sources,
            &test_ids,
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
                &test_ids,
            )
            .is_empty()
        );
    }

    #[test]
    fn owner_must_be_allowed() {
        let (statuses, sources, test_ids) = contexts();
        let violations = check_capability(
            0,
            &cap("account.login", "account", "required", "someone"),
            &statuses,
            &sources,
            &test_ids,
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains("not an allowed owner"))
        );
    }

    #[test]
    fn unknown_status_and_source_are_rejected() {
        let (statuses, sources, test_ids) = contexts();
        let mut capability = cap("account.login", "account", "dreaming", "protonwire-api");
        capability.sources = vec!["nowhere".to_string()];
        let violations = check_capability(0, &capability, &statuses, &sources, &test_ids);
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
        let (statuses, sources, test_ids) = contexts();
        let mut capability = cap("account.login", "account", "required", "protonwire-api");
        capability.tests = vec!["T-1".to_string(), "unit-9".to_string()];
        let violations = check_capability(0, &capability, &statuses, &sources, &test_ids);
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

        // FU-F (round-6 verdict residual): the second loop in
        // check_upstream — the any-further-entry rule — had NO test, so
        // deleting it passed the whole suite and its preservation was
        // inspection-level only. An upstream entry OUTSIDE the pinned
        // names (here a revision-less official_bb10_app) must still be
        // named as a violation by that loop.
        if let Some(upstream) = doc.upstream.as_mut() {
            upstream.insert(
                "official_bb10_app".to_string(),
                UpstreamEntry {
                    version: None,
                    revision: None,
                    checksum_sha256: None,
                },
            );
        }
        assert!(
            check_upstream(&doc, &good_lock())
                .iter()
                .any(|v| v.contains("official_bb10_app")),
            "a revision-less extra upstream entry must be named as a violation"
        );
    }
}
