//! License inventory and the distribution release guard (compliance
//! findings 2+3): the pinned Proton registry crates carry no license
//! manifest, so redistribution is blocked (COPYING.md, PRD NFR-35/OQ-2).
//!
//! `license-scan` enumerates every resolved package with no license field
//! and fails on drift against the recorded baseline, so an engine upgrade
//! cannot silently grow the blocked set. It also classifies every declared
//! license against GPL-3.0-or-later compatibility (NFR-35: ProTUN is
//! GPL-3.0-or-later, so every linked dependency must be too): legacy slash
//! separators mean OR, OR needs any compatible branch, AND needs every
//! branch, and anything the classifier does not recognize fails loud for a
//! human to classify.
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

/// SPDX IDs compatible with the workspace's GPL-3.0-or-later terms
/// (NFR-35). `GPL-3.0` additionally accepts any `GPL-3.0-*` suffix form
/// (`GPL-3.0-only`, `GPL-3.0-or-later`), and `LLVM-exception` is the one
/// accepted exception suffix. Everything else is either a known
/// incompatible GPL-2.0 form or unrecognized (fail loud).
const GPL3_COMPATIBLE: &[&str] = &[
    "MIT",
    "MIT-0",
    "Apache-2.0",
    "BSD-1-Clause",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "0BSD",
    "Unlicense",
    "MPL-2.0",
    "GPL-2.0-or-later",
    "LGPL-2.1-or-later",
    "LGPL-3.0-or-later",
    "BSL-1.0",
    "CC0-1.0",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "CDLA-Permissive-2.0",
    "bzip2-1.0.6",
    "WTFPL",
];

/// The GPL-3.0-or-later compatibility verdict for one license expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Compatibility {
    /// Redistributable under GPL-3.0-or-later.
    Compatible,
    /// Recognized as incompatible (the GPL-2.0 family short of the
    /// allowlisted `GPL-2.0-or-later`).
    Incompatible,
    /// Unknown token or malformed expression — a human must classify it
    /// and, if warranted, extend the allowlist.
    Unrecognized,
}

impl Compatibility {
    /// An OR branch satisfies the whole expression when any branch does;
    /// an unrecognized branch always fails loud.
    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unrecognized, _) | (_, Self::Unrecognized) => Self::Unrecognized,
            (Self::Compatible, _) | (_, Self::Compatible) => Self::Compatible,
            (Self::Incompatible, Self::Incompatible) => Self::Incompatible,
        }
    }

    /// An AND expression needs every branch; an unrecognized or
    /// incompatible branch sinks it.
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unrecognized, _) | (_, Self::Unrecognized) => Self::Unrecognized,
            (Self::Incompatible, _) | (_, Self::Incompatible) => Self::Incompatible,
            (Self::Compatible, Self::Compatible) => Self::Compatible,
        }
    }
}

/// Classifies one `license` field value against GPL-3.0-or-later
/// compatibility (NFR-35): legacy '/' separators mean OR, OR is satisfied
/// by any compatible branch, AND (parens included) by every branch, and
/// unknown tokens or malformed expressions return `Unrecognized`.
pub(crate) fn classify(raw: &str) -> Compatibility {
    // Legacy slash forms ("MIT/Apache-2.0", "Apache-2.0 / MIT",
    // "Unlicense/MIT") are OR expressions, and parens must stand alone as
    // tokens; no SPDX ID contains '/', '(' or ')'.
    let normalized = raw
        .replace('/', " OR ")
        .replace('(', " ( ")
        .replace(')', " ) ");
    let tokens: Vec<&str> = normalized.split_whitespace().collect();
    let mut pos = 0;
    let verdict = parse_or(&tokens, &mut pos);
    if pos != tokens.len() {
        // Trailing tokens: an unbalanced ')' or keyword.
        return Compatibility::Unrecognized;
    }
    verdict
}

/// `expr := and_expr (OR and_expr)*` — AND binds tighter than OR.
fn parse_or(tokens: &[&str], pos: &mut usize) -> Compatibility {
    let mut verdict = parse_and(tokens, pos);
    while peek(tokens, *pos) == Some("OR") {
        *pos += 1;
        verdict = verdict.or(parse_and(tokens, pos));
    }
    verdict
}

/// `and_expr := primary (AND primary)*`
fn parse_and(tokens: &[&str], pos: &mut usize) -> Compatibility {
    let mut verdict = parse_primary(tokens, pos);
    while peek(tokens, *pos) == Some("AND") {
        *pos += 1;
        verdict = verdict.and(parse_primary(tokens, pos));
    }
    verdict
}

/// `primary := '(' expr ')' | id (WITH LLVM-exception)?`
fn parse_primary(tokens: &[&str], pos: &mut usize) -> Compatibility {
    match peek(tokens, *pos) {
        Some("(") => {
            *pos += 1;
            let inner = parse_or(tokens, pos);
            if peek(tokens, *pos) == Some(")") {
                *pos += 1;
                inner
            } else {
                Compatibility::Unrecognized
            }
        }
        Some(")") | Some("OR") | Some("AND") | Some("WITH") | None => Compatibility::Unrecognized,
        Some(id) => {
            *pos += 1;
            let verdict = single(id);
            // The only accepted exception suffix; any other fails loud.
            if peek(tokens, *pos) == Some("WITH") {
                *pos += 1;
                if peek(tokens, *pos) == Some("LLVM-exception") {
                    *pos += 1;
                } else {
                    return Compatibility::Unrecognized;
                }
            }
            verdict
        }
    }
}

fn peek<'t>(tokens: &[&'t str], pos: usize) -> Option<&'t str> {
    tokens.get(pos).copied()
}

/// The verdict for one bare SPDX ID.
fn single(id: &str) -> Compatibility {
    if GPL3_COMPATIBLE.contains(&id) || id == "GPL-3.0" || id.starts_with("GPL-3.0-") {
        Compatibility::Compatible
    } else if id == "GPL-2.0" || id.starts_with("GPL-2.0-") {
        // GPL-2.0-only cannot be combined with GPL-3 code; the one
        // compatible form (GPL-2.0-or-later) is allowlisted above.
        Compatibility::Incompatible
    } else {
        Compatibility::Unrecognized
    }
}

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

    // NFR-35: every declared license must be compatible with the
    // workspace's GPL-3.0-or-later terms. Unknown expressions fail loud —
    // a human classifies them and extends the allowlist if warranted.
    let mut incompatible = Vec::new();
    let mut classified = 0usize;
    for package in &metadata.packages {
        let license = package.license.as_deref().map(str::trim).unwrap_or("");
        if license.is_empty() {
            continue; // unlicensed: covered by the baseline drift rule above
        }
        classified += 1;
        match classify(license) {
            Compatibility::Compatible => {}
            Compatibility::Incompatible => incompatible.push(format!(
                "`{}` is `{license}` — incompatible with the workspace's \
                 GPL-3.0-or-later terms (NFR-35)",
                package.name
            )),
            Compatibility::Unrecognized => incompatible.push(format!(
                "`{}` is `{license}` — unrecognized license expression; \
                 classify it and extend the allowlist (NFR-35)",
                package.name
            )),
        }
    }
    reporter.rule(
        "declared licenses are GPL-3.0-or-later compatible",
        &incompatible,
    );
    Ok(reporter.finish(&format!(
        "license inventory drift + GPL-3 compatibility ({classified} licensed package(s))"
    )))
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

    #[test]
    fn gpl2_only_is_incompatible() {
        // The NFR-35 regression: a GPL-2.0-only dependency cannot be
        // combined with the workspace's GPL-3.0-or-later terms.
        assert_eq!(classify("GPL-2.0-only"), Compatibility::Incompatible);
        assert_eq!(classify("GPL-2.0"), Compatibility::Incompatible);
    }

    #[test]
    fn gpl3_compatible_licenses_pass() {
        for id in [
            "MIT",
            "MIT-0",
            "Apache-2.0",
            "BSD-1-Clause",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "ISC",
            "Zlib",
            "0BSD",
            "Unlicense",
            "MPL-2.0",
            "GPL-2.0-or-later",
            "LGPL-2.1-or-later",
            "LGPL-3.0-or-later",
            "BSL-1.0",
            "CC0-1.0",
            "Unicode-3.0",
            "Unicode-DFS-2016",
            "CDLA-Permissive-2.0",
            "bzip2-1.0.6",
            "WTFPL",
            // GPL-3.0 accepts any suffix form.
            "GPL-3.0",
            "GPL-3.0-only",
            "GPL-3.0-or-later",
        ] {
            assert_eq!(classify(id), Compatibility::Compatible, "{id}");
        }
    }

    #[test]
    fn or_semantics_accept_any_compatible_branch() {
        assert_eq!(classify("MIT OR Apache-2.0"), Compatibility::Compatible);
        assert_eq!(classify("GPL-2.0-only OR MIT"), Compatibility::Compatible);
        assert_eq!(
            classify("GPL-2.0-only OR GPL-2.0"),
            Compatibility::Incompatible
        );
    }

    #[test]
    fn and_semantics_require_every_branch() {
        assert_eq!(
            classify("MIT AND (Apache-2.0 OR BSD-2-Clause)"),
            Compatibility::Compatible
        );
        assert_eq!(
            classify("MIT AND GPL-2.0-only"),
            Compatibility::Incompatible
        );
    }

    #[test]
    fn legacy_slash_separators_mean_or() {
        assert_eq!(classify("MIT/Apache-2.0"), Compatibility::Compatible);
        assert_eq!(classify("Apache-2.0 / MIT"), Compatibility::Compatible);
        assert_eq!(classify("Unlicense/MIT"), Compatibility::Compatible);
        assert_eq!(classify("Apache-2.0/MIT"), Compatibility::Compatible);
    }

    #[test]
    fn llvm_exception_suffix_is_allowed() {
        assert_eq!(
            classify("Apache-2.0 WITH LLVM-exception"),
            Compatibility::Compatible
        );
        assert_eq!(
            classify("Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT"),
            Compatibility::Compatible
        );
        // Any other exception is unknown: fail loud, human classifies.
        assert_eq!(
            classify("MIT WITH Some-exception"),
            Compatibility::Unrecognized
        );
    }

    #[test]
    fn unknown_tokens_fail_loud() {
        assert_eq!(classify("AGPL-3.0-only"), Compatibility::Unrecognized);
        assert_eq!(
            classify("MIT OR Mystery-License"),
            Compatibility::Unrecognized
        );
        assert_eq!(
            classify("MIT AND (AGPL-3.0-only OR Apache-2.0)"),
            Compatibility::Unrecognized
        );
    }

    #[test]
    fn malformed_expressions_fail_loud() {
        assert_eq!(classify("(MIT"), Compatibility::Unrecognized);
        assert_eq!(classify("MIT)"), Compatibility::Unrecognized);
        assert_eq!(classify(""), Compatibility::Unrecognized);
    }

    #[test]
    fn real_tree_expressions_classify() {
        // A sample of the exact expressions `cargo metadata` reports for
        // the current resolution, including the legacy slash forms and the
        // parenthesized AND expressions.
        for expr in [
            "MIT OR Apache-2.0",
            "Apache-2.0 OR MIT",
            "Unicode-3.0",
            "Zlib OR Apache-2.0 OR MIT",
            "GPL-3.0-or-later",
            "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
            "Unlicense OR MIT",
            "Unlicense/MIT",
            "Apache-2.0 / MIT",
            "(MIT OR Apache-2.0) AND Unicode-DFS-2016",
            "(MIT OR Apache-2.0) AND Unicode-3.0",
            "MIT AND Unicode-DFS-2016",
            "CC0-1.0 OR MIT-0 OR Apache-2.0",
            "Apache-2.0 AND MIT",
            "Apache-2.0 OR BSL-1.0",
            "MIT OR Apache-2.0 OR LGPL-2.1-or-later",
            "bzip2-1.0.6",
            "Apache-2.0 WITH LLVM-exception",
        ] {
            assert_eq!(classify(expr), Compatibility::Compatible, "{expr}");
        }
    }
}
