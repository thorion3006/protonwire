//! `cargo xtask dep-graph` — enforces the monorepo dependency rules
//! (PRD T-23 / NFR-39): frontends only talk to `protonwire-client`, core-side
//! crates stay frontend-agnostic, `ratatui`/`tauri` stay inside their apps,
//! exactly one workspace `Cargo.lock` exists, and no dependency uses a
//! wildcard version.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow};
use cargo_metadata::{Metadata, Package};

use crate::Reporter;

/// Frontends and the client SDK must reach the service only through
/// `protonwire-client`; never the engines or deep crates directly.
const CLIENT_SIDE: &[&str] = &[
    "protonwire-cli",
    "protonwire-tui",
    "protonwire-gui",
    "protonwire-client",
];
const DEEP_DEPS: &[&str] = &[
    "protonwire-core",
    "protonwire-net",
    "protonwire-store",
    "protonwire-protocol",
    "protonwire-api",
    "protonwire-policy",
    "protonwire-pf",
    "protun",
    "muon",
];

/// Core-side crates must not depend on any frontend or frontend technology.
const CORE_SIDE: &[&str] = &[
    "protonwire-core",
    "protonwire-api",
    "protonwire-protocol",
    "protonwire-net",
    "protonwire-policy",
    "protonwire-pf",
    "protonwire-store",
    "protonwire-ipc",
    "protonwire-frontend-api",
];
const FRONTEND_TECH: &[&str] = &[
    "protonwire-cli",
    "protonwire-tui",
    "protonwire-gui",
    "protonwire-client",
    "clap",
    "ratatui",
    "tauri",
    "tauri-build",
];

pub fn run(root: &Path) -> Result<bool> {
    let metadata = cargo_metadata(root)?;
    let mut reporter = Reporter::new("dep-graph");

    let mut members: Vec<&Package> = metadata
        .workspace_members
        .iter()
        .map(|id| metadata.packages.iter().find(|package| package.id == *id))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| anyhow!("workspace member missing from metadata packages"))?;
    members.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    let mut edge_violations = Vec::new();
    let mut placement_violations = Vec::new();
    let mut edges_checked = 0usize;
    for package in &members {
        let deps: Vec<&str> = package
            .dependencies
            .iter()
            .map(|dependency| dependency.name.as_str())
            .collect();
        edges_checked += deps.len();
        edge_violations.extend(forbidden_edges(&package.name, &deps));
        let manifest_rel = package
            .manifest_path
            .as_std_path()
            .strip_prefix(metadata.workspace_root.as_std_path())
            .map(|rel| rel.to_string_lossy().into_owned())
            .unwrap_or_else(|_| package.manifest_path.to_string());
        placement_violations.extend(ui_crate_placement(&manifest_rel, &deps));
    }
    reporter.rule("forbidden dependency edges", &edge_violations);
    reporter.rule("UI crate placement", &placement_violations);

    let mut lockfile_violations = Vec::new();
    let expected_lockfile = root.join("Cargo.lock");
    if !expected_lockfile.is_file() {
        lockfile_violations.push(format!(
            "workspace lockfile {} is missing",
            expected_lockfile.display()
        ));
    }
    for lockfile in find_lock_files(root) {
        if lockfile != expected_lockfile {
            lockfile_violations.push(format!(
                "unexpected additional lockfile at {}",
                lockfile.display()
            ));
        }
    }
    // The lockfile must be UNDER VERSION CONTROL, not merely present on
    // disk: PRD 6.5 makes it the resolution authority for the lockless
    // ProTUN pin, and a developer-global gitignore entry (a common Rust
    // setup) silently excludes it otherwise (FR-127A).
    if !lockfile_tracked_by_git(root) {
        lockfile_violations.push(
            "Cargo.lock exists on disk but is NOT tracked by git — add a \
             `!Cargo.lock` negation to the repo .gitignore and commit it"
                .to_string(),
        );
    }
    reporter.rule("single workspace Cargo.lock", &lockfile_violations);

    let mut wildcard_violations = Vec::new();
    for package in &members {
        let manifest = fs::read_to_string(package.manifest_path.as_std_path())
            .with_context(|| format!("failed to read {}", package.manifest_path))?;
        for violation in wildcard_versions(&manifest) {
            wildcard_violations.push(format!("{}: {violation}", package.manifest_path));
        }
    }
    reporter.rule("no wildcard dependency versions", &wildcard_violations);

    let summary = format!(
        "{} workspace members, {} direct dependency edges checked",
        members.len(),
        edges_checked
    );
    Ok(reporter.finish(&summary))
}

pub(crate) fn cargo_metadata(root: &Path) -> Result<Metadata> {
    let output = run_cargo(root, &["metadata", "--format-version", "1"])?;
    serde_json::from_str(&output).context("failed to parse `cargo metadata` output")
}

fn run_cargo(root: &Path, args: &[&str]) -> Result<String> {
    // `cargo` from PATH first, then $CARGO_HOME/bin/cargo for setups where
    // the cargo bin directory is not on PATH (rust-review nit: no
    // developer-machine absolute paths in the repo).
    let mut candidates: Vec<String> = vec!["cargo".to_string()];
    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        candidates.push(format!("{cargo_home}/bin/cargo"));
    }
    for binary in candidates {
        match Command::new(&binary).args(args).current_dir(root).output() {
            Ok(output) if output.status.success() => {
                return String::from_utf8(output.stdout).with_context(|| {
                    format!("`{binary} {}` produced non-UTF-8 output", args.join(" "))
                });
            }
            Ok(output) => {
                return Err(anyhow!(
                    "`{binary} {}` failed ({}):\n{}",
                    args.join(" "),
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(anyhow!("failed to run `{binary} {}`", args.join(" "))).context(err);
            }
        }
    }
    Err(anyhow!(
        "no usable cargo binary found; tried `cargo` on PATH and `$CARGO_HOME/bin/cargo`"
    ))
}

/// Direct-dependency rules by package name.
pub(crate) fn forbidden_edges(member: &str, deps: &[&str]) -> Vec<String> {
    let mut violations = Vec::new();
    if CLIENT_SIDE.contains(&member) {
        for dep in deps {
            if DEEP_DEPS.contains(dep) {
                violations.push(format!(
                    "{member} -> {dep} is forbidden: frontends reach the service only through protonwire-client (T-23)"
                ));
            }
        }
    }
    if CORE_SIDE.contains(&member) {
        for dep in deps {
            if FRONTEND_TECH.contains(dep) {
                violations.push(format!(
                    "{member} -> {dep} is forbidden: core-side crates stay frontend-agnostic (NFR-39)"
                ));
            }
        }
    }
    violations
}

/// UI technology is confined to its app directory.
pub(crate) fn ui_crate_placement(manifest_rel: &str, deps: &[&str]) -> Vec<String> {
    let rel = manifest_rel.replace('\\', "/");
    let mut violations = Vec::new();
    if deps.contains(&"ratatui") && !rel.starts_with("apps/tui/") {
        violations.push(format!(
            "ratatui is only allowed under apps/tui/ (found {rel})"
        ));
    }
    for crate_name in ["tauri", "tauri-build"] {
        if deps.contains(&crate_name) && !rel.starts_with("apps/gui/") {
            violations.push(format!(
                "{crate_name} is only allowed under apps/gui/ (found {rel})"
            ));
        }
    }
    violations
}

/// Recursively collect every `Cargo.lock`, skipping `.git` and `target`.
pub(crate) fn find_lock_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    walk_for_lock_files(dir, &mut found);
    found.sort();
    found
}

/// Whether git tracks the root `Cargo.lock`. A developer-global gitignore
/// commonly excludes Rust lockfiles for libraries; for this application
/// workspace the committed lockfile is the resolution authority, so its
/// absence from the index is a supply-chain regression (FR-127A).
pub(crate) fn lockfile_tracked_by_git(root: &Path) -> bool {
    let output = std::process::Command::new("git")
        .arg("ls-files")
        .arg("--error-unmatch")
        .arg("--")
        .arg("Cargo.lock")
        .current_dir(root)
        .output();
    matches!(output, Ok(out) if out.status.success())
}

fn walk_for_lock_files(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if file_type.is_dir() {
            if name == ".git" || name == "target" {
                continue;
            }
            walk_for_lock_files(&path, found);
        } else if name == "Cargo.lock" {
            found.push(path);
        }
    }
}

/// Reject any dependency whose version is the wildcard `"*"`.
pub(crate) fn wildcard_versions(manifest: &str) -> Vec<String> {
    let Ok(table) = toml::from_str::<toml::Table>(manifest) else {
        return vec!["manifest is not valid TOML".to_string()];
    };
    let mut violations = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(entries) = table.get(section) {
            scan_dependency_entries(section, entries, &mut violations);
        }
    }
    if let Some(targets) = table.get("target").and_then(toml::Value::as_table) {
        for (target, cfg_table) in targets {
            for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(entries) = cfg_table.get(section) {
                    scan_dependency_entries(
                        &format!("target.{target}.{section}"),
                        entries,
                        &mut violations,
                    );
                }
            }
        }
    }
    violations
}

fn scan_dependency_entries(section: &str, entries: &toml::Value, violations: &mut Vec<String>) {
    let Some(entries) = entries.as_table() else {
        return;
    };
    for (name, spec) in entries {
        let version = match spec {
            toml::Value::String(version) => Some(version.as_str()),
            toml::Value::Table(spec) => spec.get("version").and_then(toml::Value::as_str),
            _ => None,
        };
        if version == Some("*") {
            violations.push(format!(
                "[{section}] dependency `{name}` uses version \"*\""
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontends_cannot_reach_deep_crates() {
        assert!(
            !forbidden_edges(
                "protonwire-cli",
                &["protonwire-client", "protonwire-core", "anyhow"]
            )
            .is_empty()
        );
        assert!(
            !forbidden_edges("protonwire-tui", &["ratatui", "protonwire-client", "muon"])
                .is_empty()
        );
        assert!(!forbidden_edges("protonwire-gui", &["protonwire-net"]).is_empty());
        assert!(!forbidden_edges("protonwire-client", &["protun"]).is_empty());
        assert!(forbidden_edges("protonwire-client", &["protonwire-ipc", "anyhow"]).is_empty());
    }

    #[test]
    fn daemon_may_depend_on_core() {
        assert!(
            forbidden_edges("protonwire-daemon", &["protonwire-core", "protonwire-net"]).is_empty()
        );
    }

    #[test]
    fn core_side_cannot_depend_on_frontend_tech() {
        assert!(!forbidden_edges("protonwire-core", &["protonwire-client", "clap"]).is_empty());
        assert!(!forbidden_edges("protonwire-frontend-api", &["ratatui"]).is_empty());
        assert!(!forbidden_edges("protonwire-store", &["protonwire-gui"]).is_empty());
        assert!(forbidden_edges("protonwire-core", &["serde", "protun"]).is_empty());
    }

    #[test]
    fn ui_technology_is_confined() {
        assert!(ui_crate_placement("apps/tui/Cargo.toml", &["ratatui", "anyhow"]).is_empty());
        assert!(
            ui_crate_placement("apps/gui/src-tauri/Cargo.toml", &["tauri", "tauri-build"])
                .is_empty()
        );
        assert!(!ui_crate_placement("apps/cli/Cargo.toml", &["clap", "ratatui"]).is_empty());
        assert!(!ui_crate_placement("crates/core/Cargo.toml", &["tauri"]).is_empty());
        assert!(ui_crate_placement("apps/cli/Cargo.toml", &["clap"]).is_empty());
    }

    #[test]
    fn wildcard_versions_are_rejected() {
        let manifest = r#"
[dependencies]
serde = "1"
wildcard = "*"
table-star = { version = "*" }
table-ok = { version = "1", features = ["x"] }
workspace-dep = { workspace = true }

[dev-dependencies]
dev-star = "*"

[target.'cfg(unix)'.dependencies]
nix-star = "*"

[target.'cfg(unix)'.build-dependencies]
build-star = "*"
"#;
        let violations = wildcard_versions(manifest);
        let text = violations.join("\n");
        for expected in [
            "dependency `wildcard`",
            "dependency `table-star`",
            "dependency `dev-star`",
            "dependency `nix-star`",
            "dependency `build-star`",
        ] {
            assert!(text.contains(expected), "missing {expected} in {text}");
        }
        assert!(!text.contains("`serde`"));
        assert!(!text.contains("`table-ok`"));
        assert!(!text.contains("`workspace-dep`"));
    }

    #[test]
    fn invalid_toml_is_reported() {
        assert_eq!(
            wildcard_versions("not [valid toml"),
            vec!["manifest is not valid TOML".to_string()]
        );
    }

    #[test]
    fn lock_file_walk_skips_git_and_target() {
        let root = std::env::temp_dir().join(format!("xtask-deps-walk-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("crates/core")).unwrap();
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join("Cargo.lock"), "").unwrap();
        fs::write(root.join("crates/core/Cargo.toml"), "").unwrap();
        fs::write(root.join("crates/Cargo.lock"), "").unwrap();
        fs::write(root.join("target/Cargo.lock"), "").unwrap();
        fs::write(root.join(".git/Cargo.lock"), "").unwrap();

        let found = find_lock_files(&root);
        let relative: Vec<String> = found
            .iter()
            .map(|path| {
                path.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(relative, ["Cargo.lock", "crates/Cargo.lock"]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn deep_dep_set_is_complete() {
        let deep: std::collections::BTreeSet<&str> = DEEP_DEPS.iter().copied().collect();
        for crate_name in ["protonwire-core", "protun", "muon", "protonwire-pf"] {
            assert!(deep.contains(crate_name));
        }
    }
}
