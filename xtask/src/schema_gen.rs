//! `cargo xtask schema-gen [--check]` — regenerates the versioned frontend
//! JSON Schemas from `protonwire_frontend_api::schema::root_schemas()` into
//! `schemas/frontend/v1/`. With `--check`, nothing is written and the command
//! fails listing files that are missing, stale, or obsolete.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::Reporter;

const SCHEMA_DIR: &str = "schemas/frontend/v1";

pub fn run(root: &Path, check: bool) -> Result<bool> {
    let dir = root.join(SCHEMA_DIR);
    let schemas = protonwire_frontend_api::schema::root_schemas();

    if !check {
        write_all(&dir, &schemas)?;
        println!(
            "PASS [schema-gen] wrote {} schema file(s) to {}",
            schemas.len(),
            dir.display()
        );
        return Ok(true);
    }

    let violations = check_dir(&dir, &schemas);
    let mut reporter = Reporter::new("schema-gen");
    reporter.rule("generated schemas are up to date", &violations);
    let summary = format!("{} schema(s) in {SCHEMA_DIR}", schemas.len());
    Ok(reporter.finish(&summary))
}

fn render(schema: &schemars::Schema) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(schema).expect("schema serialization cannot fail");
    bytes.push(b'\n');
    bytes
}

fn write_all(dir: &Path, schemas: &[(&'static str, schemars::Schema)]) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    for (name, schema) in schemas {
        let path = dir.join(format!("{name}.schema.json"));
        fs::write(&path, render(schema))
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    Ok(())
}

fn check_dir(dir: &Path, schemas: &[(&'static str, schemars::Schema)]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut expected: BTreeSet<String> = BTreeSet::new();
    for (name, schema) in schemas {
        let file_name = format!("{name}.schema.json");
        let path = dir.join(&file_name);
        expected.insert(file_name);
        match fs::read(&path) {
            Ok(existing) if existing == render(schema) => {}
            Ok(_) => violations.push(format!(
                "{} is stale; rerun `cargo xtask schema-gen`",
                path.display()
            )),
            Err(_) => violations.push(format!(
                "{} is missing; rerun `cargo xtask schema-gen`",
                path.display()
            )),
        }
    }
    // Codex PR review finding 14: a root schema that was renamed or removed
    // leaves its old committed file behind, and inspecting only the schemas
    // root_schemas() still returns let that obsolete file keep shipping as
    // part of the versioned API. Anything in the directory outside the
    // expected set fails the check.
    if let Ok(entries) = fs::read_dir(dir) {
        let present: BTreeSet<String> = entries
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".json"))
            .collect();
        for extra in present.difference(&expected) {
            violations.push(format!(
                "{} is not a generated schema; remove the obsolete file",
                dir.join(extra).display()
            ));
        }
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schemas() -> Vec<(&'static str, schemars::Schema)> {
        protonwire_frontend_api::schema::root_schemas()
    }

    #[test]
    fn every_schema_renders_as_pretty_json_with_trailing_newline() {
        assert!(!schemas().is_empty());
        for (name, schema) in schemas() {
            let bytes = render(&schema);
            assert_eq!(bytes.last(), Some(&b'\n'), "{name} must end with a newline");
            assert!(
                serde_json::from_slice::<serde_json::Value>(&bytes).is_ok(),
                "{name} must be valid JSON"
            );
        }
    }

    #[test]
    fn check_mode_detects_missing_and_stale_files() {
        let dir = std::env::temp_dir().join(format!("xtask-schema-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let all = schemas();
        write_all(&dir, &all).unwrap();
        assert!(check_dir(&dir, &all).is_empty());

        let (missing_name, _) = &all[0];
        let (stale_name, _) = &all[1];
        fs::remove_file(dir.join(format!("{missing_name}.schema.json"))).unwrap();
        fs::write(dir.join(format!("{stale_name}.schema.json")), b"{}\n").unwrap();

        let violations = check_dir(&dir, &all);
        assert_eq!(violations.len(), 2);
        assert!(
            violations.iter().any(
                |v| v.contains(&format!("{missing_name}.schema.json")) && v.contains("missing")
            )
        );
        assert!(
            violations
                .iter()
                .any(|v| v.contains(&format!("{stale_name}.schema.json")) && v.contains("stale"))
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Codex PR review finding 14 (P2): --check only inspected the schemas
    /// root_schemas() still returns, so a renamed/removed root left its old
    /// committed .schema.json invisible to the gate — an obsolete file
    /// shipping as part of the versioned API forever. Extra files in the
    /// directory must fail the check.
    #[test]
    fn check_mode_rejects_obsolete_files_left_in_the_directory() {
        let dir = std::env::temp_dir().join(format!("xtask-schema-extra-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let all = schemas();
        write_all(&dir, &all).unwrap();
        assert!(
            check_dir(&dir, &all).is_empty(),
            "exact directory must be clean"
        );

        fs::write(dir.join("obsolete-root.schema.json"), b"{}\n").unwrap();
        let violations = check_dir(&dir, &all);
        assert_eq!(
            violations.len(),
            1,
            "the obsolete file must be the only violation: {violations:?}"
        );
        assert!(
            violations[0].contains("obsolete-root.schema.json"),
            "violation must name the file: {violations:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
