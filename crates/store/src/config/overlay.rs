//! Per-UID user overlay: presentation preferences and per-user selectors
//! only. Any system-only key here is a parse error by construction
//! (`deny_unknown_fields`); the daemon revalidates on its side as well —
//! T-37 lands with the overlay IPC in Milestone 2 (PRD section 10).

use serde::{Deserialize, Serialize};

use super::Authority;

/// Client output format preference (per-UID overlay field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum OutputFormat {
    /// Human-readable output.
    #[default]
    Human,
    /// Machine-readable JSON output.
    Json,
}

/// Per-UID user overlay: presentation preferences and per-user selectors
/// only. Any system-only key here is a parse error by construction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UserOverlay {
    /// Schema version (same generation as the system document).
    pub schema_version: u32,
    /// Presentation preferences.
    pub presentation: UserPresentation,
}

impl UserOverlay {
    /// Field-level authority report for the overlay document (T-37
    /// groundwork): every field of the typed surface carries exactly one
    /// entry, and every overlay field is per-user by construction — the
    /// document itself only allows presentation preferences and
    /// selectors, so no entry can be `System` without the schema
    /// contradicting itself (the system document's table is the mirror
    /// image: none of its fields may appear here).
    pub fn authority_report(&self) -> Vec<(&'static str, Authority)> {
        vec![
            ("schema_version", Authority::PerUser),
            ("presentation.default_output", Authority::PerUser),
        ]
    }
}

/// Presentation preferences.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UserPresentation {
    /// Default CLI output format.
    pub default_output: Option<OutputFormat>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_overlay_rejects_system_only_fields() {
        let overlay = "schema_version: 2\ndaemon:\n  log_level: debug\n";
        let err = crate::yaml::from_str::<UserOverlay>(overlay).unwrap_err();
        assert!(err.to_string().contains("daemon"), "got: {err}");
    }

    #[test]
    fn user_overlay_parses_presentation() {
        let overlay = "schema_version: 2\npresentation:\n  default_output: json\n";
        let parsed: UserOverlay = crate::yaml::from_str(overlay).unwrap();
        assert_eq!(parsed.presentation.default_output, Some(OutputFormat::Json));
    }

    /// T-37 groundwork: the overlay's authority table covers every field
    /// of its typed surface and every entry is per-user. Red evidence is
    /// the disclosed compile-red (`UserOverlay::authority_report` did not
    /// exist on this commit's parent).
    #[test]
    fn overlay_authority_report_covers_every_typed_field() {
        let overlay = UserOverlay {
            schema_version: 2,
            presentation: UserPresentation {
                default_output: Some(OutputFormat::Json),
            },
        };
        let rendered = serde_norway::to_value(&overlay).unwrap();
        let report = overlay.authority_report();
        let mut leaves = Vec::new();
        walk_leaf_paths(&rendered, "", &report, &mut leaves);
        assert!(!leaves.is_empty(), "the walk must find the overlay fields");

        for leaf in &leaves {
            let entries: Vec<_> = report
                .iter()
                .filter(|(path, _)| *path == leaf.as_str())
                .collect();
            assert_eq!(
                entries.len(),
                1,
                "field {leaf} must carry exactly one authority entry (found {})",
                entries.len()
            );
        }
        for (path, authority) in &report {
            assert_eq!(
                *authority,
                Authority::PerUser,
                "overlay field {path} must be per-user"
            );
        }
    }

    /// Walks every leaf field path of a serialized document (mirrors the
    /// system-document walker in the parent module's tests).
    fn walk_leaf_paths(
        value: &serde_norway::Value,
        prefix: &str,
        report: &[(&'static str, Authority)],
        out: &mut Vec<String>,
    ) {
        match value {
            serde_norway::Value::Mapping(mapping) => {
                if !prefix.is_empty() && report.iter().any(|(path, _)| *path == prefix) {
                    out.push(prefix.to_owned());
                    return;
                }
                for (key, val) in mapping {
                    let key = key.as_str().expect("overlay keys serialize as strings");
                    let path = if prefix.is_empty() {
                        key.to_owned()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    walk_leaf_paths(val, &path, report, out);
                }
            }
            serde_norway::Value::Sequence(sequence) => {
                let of_mappings = !sequence.is_empty()
                    && sequence
                        .iter()
                        .all(|element| matches!(element, serde_norway::Value::Mapping(_)));
                if of_mappings {
                    for element in sequence {
                        walk_leaf_paths(element, &format!("{prefix}[]"), report, out);
                    }
                } else {
                    out.push(prefix.to_owned());
                }
            }
            _ => out.push(prefix.to_owned()),
        }
    }
}
