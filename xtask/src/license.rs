//! License inventory and the distribution release guard (compliance
//! findings 2+3): the pinned Proton registry crates carry no license
//! manifest, so redistribution is blocked (COPYING.md, PRD NFR-35/OQ-2).
//!
//! `license-scan` enumerates every resolved package with no license field
//! and fails on drift against the recorded baseline, so an engine upgrade
//! cannot silently grow the blocked set.
//!
//! `release-guard` fails unless `docs/LICENSE-CLEARANCE.md` exists — the
//! documentation-only blocker becomes an enforced gate for tag builds.

use std::path::Path;

use anyhow::Result;

use crate::Reporter;

/// The recorded baseline of packages with no license field in the current
/// resolution (all Proton registry/git crates; see docs/review-log.md and
/// COPYING.md). Distribution is blocked until Proton supplies terms for
/// every entry (OQ-2).
const KNOWN_UNLICENSED: &[&str] = &[
    "muon",
    "muon-rest",
    "protun",
    "proton-os-interface",
    "proton-pfff",
    "proton-pfff-config",
    "proton-pfff-core",
    "proton-pfff-module",
    "proton-tls-parser",
    "proton-vpn-haproxyv2",
    "proton-vpn-local-agent",
    "proton-vpn-netstack",
    "proton-vpn-rcrl",
    "proton-vpn-toolkit",
    "proton-vpn-utils",
    "proton-vpn-yaourt",
    "pvpnclient",
];

/// The clearance marker whose existence unblocks releases.
pub const CLEARANCE_MARKER: &str = "docs/LICENSE-CLEARANCE.md";

/// Classifies the live unlicensed set against the baseline: returns the
/// newly blocked names (violations) and the resolved names (baseline
/// entries that now carry a license — informational, but the baseline
/// should be updated).
pub(crate) fn drift<'a>(unlicensed: &[String], known: &[&'a str]) -> (Vec<String>, Vec<&'a str>) {
    let newly_blocked = unlicensed
        .iter()
        .filter(|name| !known.contains(&name.as_str()))
        .cloned()
        .collect();
    let resolved = known
        .iter()
        .copied()
        .filter(|known_name| !unlicensed.iter().any(|live| live == known_name))
        .collect();
    (newly_blocked, resolved)
}

/// The release decision: distribution requires the clearance marker.
pub(crate) fn release_allowed(clearance_exists: bool) -> Result<(), String> {
    if clearance_exists {
        Ok(())
    } else {
        Err(format!(
            "distribution is blocked: Proton registry crates carry no license; create \
             {CLEARANCE_MARKER} only after license clearance (see COPYING.md and \
             docs/official-parity.yaml upstream entries)"
        ))
    }
}

/// `cargo xtask license-scan`
pub fn run(root: &Path) -> Result<bool> {
    let mut reporter = Reporter::new("license-scan");
    let metadata = crate::deps::cargo_metadata(root)?;

    let mut unlicensed: Vec<String> = metadata
        .packages
        .iter()
        .filter(|package| package.license.as_deref().unwrap_or("").trim().is_empty())
        .map(|package| package.name.to_string())
        .collect();
    unlicensed.sort();
    unlicensed.dedup();

    let (newly_blocked, resolved) = drift(&unlicensed, KNOWN_UNLICENSED);
    reporter.rule(
        "unlicensed package set matches the recorded baseline",
        &newly_blocked
            .iter()
            .map(|name| {
                format!(
                    "`{name}` has no license field and is not in the baseline — \
                     distribution blocker grew; record it and extend COPYINGS.md \
                     outreach (OQ-2)"
                )
            })
            .collect::<Vec<_>>(),
    );
    for name in resolved {
        reporter.note(&format!(
            "`{name}` now carries a license — shrink the baseline and revisit \
             the distribution gate"
        ));
    }
    reporter.note(&format!(
        "{} unlicensed package(s) on record; distribution blocked (COPYING.md)",
        unlicensed.len()
    ));
    Ok(reporter.finish("license inventory drift check"))
}

/// `cargo xtask release-guard`
pub fn release_guard(root: &Path) -> Result<bool> {
    let mut reporter = Reporter::new("release-guard");
    let allowed = release_allowed(root.join(CLEARANCE_MARKER).is_file());
    match allowed {
        Ok(()) => {
            reporter.rule("license clearance marker present", &[]);
        }
        Err(reason) => {
            reporter.rule("license clearance marker present", &[reason]);
        }
    }
    Ok(reporter.finish("distribution gate (runs on release tags)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn no_drift_when_sets_match() {
        let (newly, resolved) = drift(&set(&["muon", "protun"]), &["muon", "protun"]);
        assert!(newly.is_empty());
        assert!(resolved.is_empty());
    }

    #[test]
    fn new_unlicensed_package_is_a_violation() {
        let (newly, resolved) = drift(&set(&["muon", "mystery-crate"]), &["muon"]);
        assert_eq!(newly, vec!["mystery-crate".to_string()]);
        assert!(resolved.is_empty());
    }

    #[test]
    fn resolved_package_is_reported_not_failed() {
        let (newly, resolved) = drift(&set(&["muon"]), &["muon", "protun"]);
        assert!(newly.is_empty());
        assert_eq!(resolved, vec!["protun"]);
    }

    #[test]
    fn release_blocked_without_clearance_marker() {
        let err = release_allowed(false).expect_err("must be blocked");
        assert!(err.contains(CLEARANCE_MARKER));
        assert!(err.contains("COPYING.md"));
        assert!(release_allowed(true).is_ok());
    }

    #[test]
    fn baseline_records_the_documented_blocked_set() {
        // The compliance review enumerated 17 unlicensed packages; keep the
        // baseline pinned to that count until clearance changes it.
        assert_eq!(KNOWN_UNLICENSED.len(), 17);
    }
}
