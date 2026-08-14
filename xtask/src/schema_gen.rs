//! `cargo xtask schema-gen [--check]` — regenerates the versioned frontend
//! JSON Schemas from `protonwire_frontend_api::schema::root_schemas()` into
//! `schemas/frontend/v1/`. With `--check`, nothing is written and the command
//! fails listing files that are missing or stale.

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
    for (name, schema) in schemas {
        let path = dir.join(format!("{name}.schema.json"));
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
}
