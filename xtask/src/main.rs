//! `cargo xtask` — validation and code-generation tooling for the ProtonWire
//! monorepo.
//!
//! Subcommands enforce the repository contracts described in
//! `docs/PRD-proton-wire.md`: the official-parity capability manifest (T-19),
//! the connection-groups catalog, the vendored UN M49 snapshot, the monorepo
//! dependency rules (T-23 / NFR-39), and the generated frontend JSON Schemas.
//!
//! Run via `cargo run -p xtask -- <subcommand>` (or `cargo xtask` with the
//! usual xtask alias). Every subcommand prints per-rule PASS/FAIL lines and a
//! summary, and exits nonzero when any rule is violated.

mod deps;
mod groups;
mod m49;
mod manifest;
mod schema_gen;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow};

const USAGE: &str = "\
usage: cargo xtask <subcommand>

subcommands:
  manifest-validate      validate docs/official-parity.yaml (parity manifest contract, T-19)
  groups-validate        validate docs/connection-groups.yaml (connection-groups contract)
  m49-verify             verify resources/geo/un-m49.csv against docs/connection-groups.yaml
  dep-graph              enforce monorepo dependency rules (forbidden edges, lockfiles, wildcards)
  schema-gen [--check]   regenerate (or check) JSON Schemas from protonwire-frontend-api
  capability-matrix      client capability matrix (stub; lands in Milestone 8, T-24)
  all                    run every check above (schema-gen in --check mode)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<bool> {
    let root = workspace_root()?;
    match args.first().map(String::as_str) {
        Some("manifest-validate") => manifest::run(&root),
        Some("groups-validate") => groups::run(&root),
        Some("m49-verify") => m49::run(&root),
        Some("dep-graph") => deps::run(&root),
        Some("schema-gen") => {
            let rest = &args[1..];
            match rest.first().map(String::as_str) {
                None => schema_gen::run(&root, false),
                Some("--check") if rest.len() == 1 => schema_gen::run(&root, true),
                _ => Err(anyhow!(
                    "unexpected schema-gen arguments: {}",
                    rest.join(" ")
                )),
            }
        }
        Some("capability-matrix") => {
            capability_matrix_stub();
            Ok(true)
        }
        Some("all") => {
            let mut ok = true;
            ok &= manifest::run(&root)?;
            ok &= groups::run(&root)?;
            ok &= m49::run(&root)?;
            ok &= deps::run(&root)?;
            ok &= schema_gen::run(&root, true)?;
            capability_matrix_stub();
            if ok {
                println!("PASS [all] every check passed");
            } else {
                println!("FAIL [all] one or more checks failed; see the FAIL lines above");
            }
            Ok(ok)
        }
        _ => {
            eprint!("{USAGE}");
            Err(anyhow!("missing or unknown subcommand"))
        }
    }
}

/// Honest stub: the client capability matrix lands in Milestone 8 (T-24).
fn capability_matrix_stub() {
    println!("STUB: client capability matrix generation lands in Milestone 8 (T-24)");
}

/// The workspace root, derived from this crate's compile-time manifest
/// directory (`<root>/xtask`), so subcommands work from any current directory.
pub(crate) fn workspace_root() -> Result<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .with_context(|| format!("cannot derive workspace root from {manifest_dir:?}"))?;
    Ok(root.to_path_buf())
}

/// Collects and prints per-rule PASS/FAIL lines for one subcommand.
pub(crate) struct Reporter {
    tool: &'static str,
    failures: usize,
}

impl Reporter {
    pub(crate) fn new(tool: &'static str) -> Self {
        Self { tool, failures: 0 }
    }

    /// Report one named rule: a single PASS line, or one FAIL line per violation.
    pub(crate) fn rule(&mut self, name: &str, violations: &[String]) {
        if violations.is_empty() {
            println!("PASS [{}] {}", self.tool, name);
        } else {
            self.failures += violations.len();
            for violation in violations {
                println!("FAIL [{}] {}: {}", self.tool, name, violation);
            }
        }
    }

    /// Print an informational (non-rule) line.
    pub(crate) fn note(&self, message: &str) {
        println!("     [{}] {}", self.tool, message);
    }

    /// Print the final summary line and return whether the subcommand passed.
    pub(crate) fn finish(self, summary: &str) -> bool {
        if self.failures == 0 {
            println!("PASS [{}] SUMMARY: {summary}", self.tool);
            true
        } else {
            println!(
                "FAIL [{}] SUMMARY: {summary}; {} violation(s)",
                self.tool, self.failures
            );
            false
        }
    }
}

// --- Shared pure predicate helpers -----------------------------------------

/// All ASCII lowercase hex characters, non-empty.
pub(crate) fn is_hex_lower(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// 64 lowercase hex characters (a sha256 digest).
pub(crate) fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && is_hex_lower(s)
}

/// 40 hex characters (a git revision).
pub(crate) fn is_git_revision(s: &str) -> bool {
    s.len() == 40 && is_hex_lower(s)
}

fn is_lower_slug(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// Matches `^[a-z0-9-]+\.[a-z0-9-]+$` (one dot, lowercase slugs on both sides).
pub(crate) fn is_capability_id(s: &str) -> bool {
    match s.split_once('.') {
        Some((area, name)) => is_lower_slug(area) && is_lower_slug(name),
        None => false,
    }
}

/// Matches `^(T|IT|E2E)-[0-9]+$`.
pub(crate) fn is_test_id(s: &str) -> bool {
    match s.split_once('-') {
        Some((prefix, number)) => {
            matches!(prefix, "T" | "IT" | "E2E")
                && !number.is_empty()
                && number.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// A violation when `actual` is not `Some(expected)`, for scalar pin checks.
pub(crate) fn expect_value(actual: Option<&str>, expected: &str, what: &str) -> Option<String> {
    match actual {
        Some(got) if got == expected => None,
        Some(got) => Some(format!("{what} must be `{expected}`, got `{got}`")),
        None => Some(format!("{what} is missing")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_helpers() {
        assert!(is_hex_lower("0123456789abcdef"));
        assert!(!is_hex_lower("0123456789ABCDEF"));
        assert!(!is_hex_lower(""));
        assert!(!is_hex_lower("0x"));
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"a".repeat(63)));
        assert!(!is_sha256_hex(&"A".repeat(64)));
        assert!(is_git_revision(&"0".repeat(40)));
        assert!(!is_git_revision(&"0".repeat(39)));
        assert!(!is_git_revision(&"0".repeat(41)));
    }

    #[test]
    fn capability_id_shape() {
        assert!(is_capability_id("account.login"));
        assert!(is_capability_id("protocol.wireguard-udp"));
        assert!(is_capability_id("a1.b2"));
        assert!(!is_capability_id("account.login.extra"));
        assert!(!is_capability_id("Account.login"));
        assert!(!is_capability_id("account_logins"));
        assert!(!is_capability_id(".login"));
        assert!(!is_capability_id("account."));
        assert!(!is_capability_id("account login"));
        assert!(!is_capability_id("account"));
        assert!(!is_capability_id(""));
    }

    #[test]
    fn test_id_shape() {
        assert!(is_test_id("T-15"));
        assert!(is_test_id("IT-29"));
        assert!(is_test_id("E2E-1"));
        assert!(!is_test_id("X-1"));
        assert!(!is_test_id("t-15"));
        assert!(!is_test_id("T-a"));
        assert!(!is_test_id("T-"));
        assert!(!is_test_id("T15"));
        assert!(!is_test_id("E2E-1-2"));
        assert!(!is_test_id("T-015x"));
    }

    #[test]
    fn expect_value_reports_missing_and_mismatch() {
        assert_eq!(expect_value(Some("x"), "x", "thing"), None);
        assert_eq!(
            expect_value(Some("y"), "x", "thing"),
            Some("thing must be `x`, got `y`".to_string())
        );
        assert_eq!(
            expect_value(None, "x", "thing"),
            Some("thing is missing".to_string())
        );
    }
}
