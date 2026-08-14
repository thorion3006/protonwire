//! `cargo xtask m49-verify` — validates the vendored UN M49 snapshot
//! (`resources/geo/un-m49.csv`) against `docs/connection-groups.yaml`:
//! the recorded sha256/source_date, the strict CSV shape, and the
//! region-code-to-primary-region mapping.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Result, anyhow};
use sha2::{Digest, Sha256};

use crate::groups;
use crate::{Reporter, is_sha256_hex};

const DEFAULT_SNAPSHOT_PATH: &str = "resources/geo/un-m49.csv";
const CSV_HEADER: &str = "m49_region_code,m49_code,iso_3166_1_alpha_2,name,region";
const MINIMUM_DATA_ROWS: usize = 150;

pub fn run(root: &Path) -> Result<bool> {
    let doc = groups::load(&root.join("docs").join("connection-groups.yaml"))?;
    let taxonomy = doc.regional_taxonomy.as_ref();
    let snapshot = taxonomy.and_then(|t| t.vendored_snapshot.as_ref());
    let mapping = region_mapping(taxonomy);
    let mut reporter = Reporter::new("m49-verify");

    // The checksum must be recorded before the snapshot can be verified.
    let recorded_sha = snapshot.and_then(|s| s.sha256.as_deref());
    let mut recorded = Vec::new();
    match recorded_sha {
        Some(sha) if is_sha256_hex(sha) => {}
        Some(sha) => recorded.push(format!(
            "vendored_snapshot.sha256 must be 64 lowercase hex characters, got `{sha}`"
        )),
        None => recorded.push("vendored M49 snapshot not yet recorded".to_string()),
    }
    match snapshot.and_then(|s| s.source_date.as_deref()) {
        Some(date) if !date.trim().is_empty() => {}
        _ => recorded.push("vendored_snapshot.source_date must be a non-empty date".to_string()),
    }
    reporter.rule(
        "vendored snapshot recorded in docs/connection-groups.yaml",
        &recorded,
    );

    let relative = snapshot
        .and_then(|s| s.required_path.clone())
        .unwrap_or_else(|| DEFAULT_SNAPSHOT_PATH.to_string());
    let csv_path = root.join(&relative);
    let read = fs::read(&csv_path);
    let mut missing = Vec::new();
    match &read {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => missing.push(format!(
            "snapshot file `{}` does not exist",
            csv_path.display()
        )),
        Err(err) => return Err(anyhow!("failed to read {}: {err}", csv_path.display())),
    }
    reporter.rule("snapshot file exists", &missing);

    if let Ok(bytes) = &read {
        let mut checksum_violations = Vec::new();
        if let Some(expected) = recorded_sha.filter(|sha| is_sha256_hex(sha)) {
            let actual = to_hex(Sha256::digest(bytes).as_slice());
            if actual != expected {
                checksum_violations.push(format!(
                    "sha256 mismatch: manifest records {expected}, file hashes to {actual}"
                ));
            }
        }
        reporter.rule("sha256 matches the recorded checksum", &checksum_violations);

        let outcome = verify_csv(bytes, &mapping);
        reporter.rule("UN M49 CSV contract", &outcome.violations);
        let per_region = outcome
            .rows_per_region
            .iter()
            .map(|(region, count)| format!("{region}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        reporter.note(&format!("rows per region: {per_region}"));
    }

    let summary = format!("vendored snapshot `{relative}` ({MINIMUM_DATA_ROWS}+ rows required)");
    Ok(reporter.finish(&summary))
}

/// m49 region code -> primary region name, derived from the taxonomy.
pub(crate) fn region_mapping(
    taxonomy: Option<&groups::RegionalTaxonomy>,
) -> BTreeMap<String, String> {
    let mut mapping = BTreeMap::new();
    if let Some(regions) = taxonomy.and_then(|t| t.primary_regions.as_ref()) {
        for (region, definition) in regions {
            if let Some(codes) = &definition.m49_codes {
                for code in codes {
                    mapping.insert(code.clone(), region.clone());
                }
            }
        }
    }
    mapping
}

pub(crate) struct CsvOutcome {
    pub violations: Vec<String>,
    pub rows_per_region: BTreeMap<String, usize>,
}

pub(crate) fn verify_csv(bytes: &[u8], mapping: &BTreeMap<String, String>) -> CsvOutcome {
    let mut outcome = CsvOutcome {
        violations: Vec::new(),
        rows_per_region: BTreeMap::new(),
    };
    for region in mapping.values().collect::<BTreeSet<_>>() {
        outcome.rows_per_region.insert((*region).clone(), 0);
    }

    if bytes.is_empty() {
        outcome.violations.push("file is empty".to_string());
        return outcome;
    }
    if bytes.last() != Some(&b'\n') {
        outcome
            .violations
            .push("file must end with a newline".to_string());
    }
    if bytes.contains(&b'\r') {
        outcome
            .violations
            .push("file must use LF line endings (found CR)".to_string());
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        outcome
            .violations
            .push("file must be valid UTF-8".to_string());
        return outcome;
    };

    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    if lines.is_empty() {
        outcome.violations.push("file has no header".to_string());
        return outcome;
    }
    if lines[0] != CSV_HEADER {
        outcome.violations.push(format!(
            "header must be exactly `{CSV_HEADER}`, got `{}`",
            lines[0]
        ));
    }

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut previous_iso: Option<String> = None;
    for (index, line) in lines.iter().enumerate().skip(1) {
        let row = index;
        if line.is_empty() {
            outcome.violations.push(format!("row {row}: blank line"));
            continue;
        }
        let fields = match parse_csv_line(line) {
            Ok(fields) => fields,
            Err(err) => {
                outcome.violations.push(format!("row {row}: {err}"));
                continue;
            }
        };
        if fields.len() != 5 {
            outcome.violations.push(format!(
                "row {row}: expected 5 fields, got {}",
                fields.len()
            ));
            continue;
        }

        let (code, m49_code, iso, name, region) = (
            fields[0].as_str(),
            fields[1].as_str(),
            fields[2].as_str(),
            fields[3].as_str(),
            fields[4].as_str(),
        );

        let expected_region = mapping.get(code);
        if expected_region.is_none() {
            outcome.violations.push(format!(
                "row {row}: m49_region_code `{code}` is not in the regional taxonomy"
            ));
        }
        if m49_code.len() != 3 || !m49_code.bytes().all(|b| b.is_ascii_digit()) {
            outcome.violations.push(format!(
                "row {row}: m49_code `{m49_code}` must be exactly 3 digits"
            ));
        }
        if iso.len() != 2 || !iso.bytes().all(|b| b.is_ascii_uppercase()) {
            outcome.violations.push(format!(
                "row {row}: iso_3166_1_alpha_2 `{iso}` must be exactly two uppercase letters"
            ));
        }
        if !seen.insert(iso.to_string()) {
            outcome
                .violations
                .push(format!("row {row}: duplicate ISO code `{iso}`"));
        }
        if let Some(previous) = &previous_iso {
            if previous.as_str() >= iso {
                outcome.violations.push(format!(
                    "row {row}: rows must be sorted ascending by ISO code (`{iso}` follows `{previous}`)"
                ));
            }
        }
        previous_iso = Some(iso.to_string());
        if let Some(expected) = expected_region {
            if region != expected.as_str() {
                outcome.violations.push(format!(
                    "row {row}: region `{region}` does not match m49_region_code `{code}` (expected `{expected}`)"
                ));
            }
        }
        if name.trim().is_empty() {
            outcome
                .violations
                .push(format!("row {row}: name must not be empty"));
        }
        *outcome
            .rows_per_region
            .entry(region.to_string())
            .or_insert(0) += 1;
    }

    let data_rows = lines.len().saturating_sub(1);
    if data_rows < MINIMUM_DATA_ROWS {
        outcome.violations.push(format!(
            "file must contain at least {MINIMUM_DATA_ROWS} data rows, found {data_rows}"
        ));
    }
    for (region, count) in &outcome.rows_per_region {
        if *count == 0 {
            outcome
                .violations
                .push(format!("region `{region}` has no rows"));
        }
    }

    outcome
}

/// Minimal RFC 4180 field parser: splits on commas, honoring double-quoted
/// fields (which may contain commas and `""` escapes).
pub(crate) fn parse_csv_line(line: &str) -> std::result::Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut chars = line.chars().peekable();

    loop {
        let mut field = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            loop {
                match chars.next() {
                    Some('"') => {
                        if chars.peek() == Some(&'"') {
                            chars.next();
                            field.push('"');
                        } else {
                            break;
                        }
                    }
                    Some(c) => field.push(c),
                    None => return Err("unterminated quoted field".to_string()),
                }
            }
            match chars.next() {
                Some(',') => {
                    fields.push(field);
                    continue;
                }
                Some(c) => return Err(format!("unexpected character {c:?} after closing quote")),
                None => {
                    fields.push(field);
                    break;
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                field.push(c);
                chars.next();
            }
            // A trailing comma yields a final (empty) field per RFC 4180.
            let consumed_comma = chars.next() == Some(',');
            fields.push(field);
            if !consumed_comma {
                break; // reached end of line without a trailing comma
            }
        }
    }

    Ok(fields)
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping() -> BTreeMap<String, String> {
        [
            ("002", "africa"),
            ("142", "asia"),
            ("150", "europe"),
            ("021", "north-america"),
            ("013", "north-america"),
            ("029", "north-america"),
            ("005", "south-america"),
            ("009", "oceania"),
        ]
        .into_iter()
        .map(|(code, region)| (code.to_string(), region.to_string()))
        .collect()
    }

    #[test]
    fn hex_helpers_agree_with_sha256() {
        assert!(is_sha256_hex(&"0".repeat(64)));
        assert!(!is_sha256_hex("0123456789ABCDEF"));
    }

    #[test]
    fn mapping_comes_from_the_taxonomy() {
        let yaml = "\
regional_taxonomy:
  primary_regions:
    africa: {m49_codes: [\"002\"]}
    oceania: {m49_codes: [\"009\"]}
";
        let doc: groups::GroupsFile = serde_norway::from_str(yaml).unwrap();
        let map = region_mapping(doc.regional_taxonomy.as_ref());
        assert_eq!(map.get("002").map(String::as_str), Some("africa"));
        assert_eq!(map.get("009").map(String::as_str), Some("oceania"));
        assert!(!map.contains_key("150"));
    }

    #[test]
    fn csv_line_parsing() {
        assert_eq!(
            parse_csv_line("002,004,AF,Afghanistan,asia").unwrap(),
            ["002", "004", "AF", "Afghanistan", "asia"]
        );
        assert_eq!(
            parse_csv_line(
                "021,060,SH,\"Saint Helena, Ascension and Tristan da Cunha\",north-america"
            )
            .unwrap()
            .len(),
            5
        );
        assert_eq!(
            parse_csv_line("a,\"say \"\"hi\"\"\",c,d,e").unwrap(),
            ["a", "say \"hi\"", "c", "d", "e"]
        );
        assert_eq!(parse_csv_line("a,b,c,d,").unwrap().len(), 5);
        assert!(parse_csv_line("a,\"unterminated,d,e").is_err());
    }

    #[test]
    fn well_formed_rows_have_no_row_violations() {
        let csv =
            format!("{CSV_HEADER}\n142,004,AF,Afghanistan,asia\n009,036,AU,Australia,oceania\n");
        let outcome = verify_csv(csv.as_bytes(), &mapping());
        assert!(
            !outcome
                .violations
                .iter()
                .any(|v| v.starts_with("row ") || v.starts_with("header")),
            "unexpected violations: {:?}",
            outcome.violations
        );
        // Small fixtures always violate the bulk expectations.
        assert!(
            outcome
                .violations
                .iter()
                .any(|v| v.contains("at least 150 data rows"))
        );
        assert!(
            outcome
                .violations
                .iter()
                .any(|v| v.contains("africa` has no rows"))
        );
        assert_eq!(outcome.rows_per_region.get("asia"), Some(&1));
        assert_eq!(outcome.rows_per_region.get("oceania"), Some(&1));
        assert_eq!(outcome.rows_per_region.get("europe"), Some(&0));
    }

    #[test]
    fn header_and_encoding_are_strict() {
        let wrong_header = verify_csv(
            b"code,m49,iso,name,region\n002,004,AF,Afghanistan,asia\n",
            &mapping(),
        );
        assert!(
            wrong_header
                .violations
                .iter()
                .any(|v| v.starts_with("header must be exactly"))
        );

        let crlf = verify_csv(
            b"m49_region_code,m49_code,iso_3166_1_alpha_2,name,region\r\n002,004,AF,Afghanistan,asia\r\n",
            &mapping(),
        );
        assert!(
            crlf.violations
                .iter()
                .any(|v| v.contains("LF line endings"))
        );

        let no_newline = verify_csv(
            b"m49_region_code,m49_code,iso_3166_1_alpha_2,name,region\n002,004,AF,Afghanistan,asia",
            &mapping(),
        );
        assert!(
            no_newline
                .violations
                .iter()
                .any(|v| v.contains("end with a newline"))
        );

        let invalid_utf8 = verify_csv(
            b"m49_region_code,m49_code,iso_3166_1_alpha_2,name,region\n002,004,AF,Af\xffghanistan,asia\n",
            &mapping(),
        );
        assert!(invalid_utf8.violations.iter().any(|v| v.contains("UTF-8")));
    }

    #[test]
    fn row_level_rules() {
        let rows = format!(
            "{CSV_HEADER}\n002,004,AF,Afghanistan,asia\n002,012,DZ,Algeria,africa\n150,020,AD,Andorra,europe\n"
        );
        let outcome = verify_csv(rows.as_bytes(), &mapping());
        assert!(
            outcome
                .violations
                .iter()
                .any(|v| v.contains("region `asia` does not match m49_region_code `002`"))
        );
        assert!(
            outcome
                .violations
                .iter()
                .any(|v| v.contains("sorted ascending"))
        );
    }

    #[test]
    fn duplicate_iso_codes_are_rejected() {
        let rows =
            format!("{CSV_HEADER}\n002,004,AF,Afghanistan,africa\n002,024,AF,Angola,africa\n");
        let outcome = verify_csv(rows.as_bytes(), &mapping());
        assert!(
            outcome
                .violations
                .iter()
                .any(|v| v.contains("duplicate ISO code `AF`"))
        );
        assert!(
            outcome
                .violations
                .iter()
                .any(|v| v.contains("sorted ascending"))
        );
    }

    #[test]
    fn bad_codes_and_names_are_rejected() {
        let rows = format!("{CSV_HEADER}\n999,4,af,\"\",asia\n");
        let outcome = verify_csv(rows.as_bytes(), &mapping());
        assert!(
            outcome
                .violations
                .iter()
                .any(|v| v.contains("m49_region_code `999` is not in the regional taxonomy"))
        );
        assert!(
            outcome
                .violations
                .iter()
                .any(|v| v.contains("m49_code `4` must be exactly 3 digits"))
        );
        assert!(
            outcome.violations.iter().any(
                |v| v.contains("iso_3166_1_alpha_2 `af` must be exactly two uppercase letters")
            )
        );
        assert!(
            outcome
                .violations
                .iter()
                .any(|v| v.contains("name must not be empty"))
        );
    }

    #[test]
    fn to_hex_matches_expected_digest_length() {
        let hex = to_hex(Sha256::digest(b"protonwire").as_slice());
        assert_eq!(hex.len(), 64);
        assert!(is_sha256_hex(&hex));
    }
}
