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

/// The complete canonical country/territory mapping the vendored UN M49
/// snapshot must carry (resources/geo/un-m49.csv): 247 rows of
/// (ISO 3166-1 alpha-2, m49_code, region) — the WO-W7 country set with
/// each country's numeric M49 code and six-continent region pinned. Set
/// equality on the ISO codes alone let GB's region code move to another
/// taxonomy-consistent value (and its m49_code change outright) without
/// a single violation; the per-row pin makes every such edit a named
/// violation.
const EXPECTED_M49_COUNTRIES: [(&str, &str, &str); 247] = [
    ("AD", "020", "europe"),
    ("AE", "784", "asia"),
    ("AF", "004", "asia"),
    ("AG", "028", "north-america"),
    ("AI", "660", "north-america"),
    ("AL", "008", "europe"),
    ("AM", "051", "asia"),
    ("AO", "024", "africa"),
    ("AR", "032", "south-america"),
    ("AS", "016", "oceania"),
    ("AT", "040", "europe"),
    ("AU", "036", "oceania"),
    ("AW", "533", "north-america"),
    ("AX", "248", "europe"),
    ("AZ", "031", "asia"),
    ("BA", "070", "europe"),
    ("BB", "052", "north-america"),
    ("BD", "050", "asia"),
    ("BE", "056", "europe"),
    ("BF", "854", "africa"),
    ("BG", "100", "europe"),
    ("BH", "048", "asia"),
    ("BI", "108", "africa"),
    ("BJ", "204", "africa"),
    ("BL", "652", "north-america"),
    ("BM", "060", "north-america"),
    ("BN", "096", "asia"),
    ("BO", "068", "south-america"),
    ("BQ", "535", "north-america"),
    ("BR", "076", "south-america"),
    ("BS", "044", "north-america"),
    ("BT", "064", "asia"),
    ("BV", "074", "south-america"),
    ("BW", "072", "africa"),
    ("BY", "112", "europe"),
    ("BZ", "084", "north-america"),
    ("CA", "124", "north-america"),
    ("CC", "166", "oceania"),
    ("CD", "180", "africa"),
    ("CF", "140", "africa"),
    ("CG", "178", "africa"),
    ("CH", "756", "europe"),
    ("CI", "384", "africa"),
    ("CK", "184", "oceania"),
    ("CL", "152", "south-america"),
    ("CM", "120", "africa"),
    ("CN", "156", "asia"),
    ("CO", "170", "south-america"),
    ("CR", "188", "north-america"),
    ("CU", "192", "north-america"),
    ("CV", "132", "africa"),
    ("CW", "531", "north-america"),
    ("CX", "162", "oceania"),
    ("CY", "196", "asia"),
    ("CZ", "203", "europe"),
    ("DE", "276", "europe"),
    ("DJ", "262", "africa"),
    ("DK", "208", "europe"),
    ("DM", "212", "north-america"),
    ("DO", "214", "north-america"),
    ("DZ", "012", "africa"),
    ("EC", "218", "south-america"),
    ("EE", "233", "europe"),
    ("EG", "818", "africa"),
    ("EH", "732", "africa"),
    ("ER", "232", "africa"),
    ("ES", "724", "europe"),
    ("ET", "231", "africa"),
    ("FI", "246", "europe"),
    ("FJ", "242", "oceania"),
    ("FK", "238", "south-america"),
    ("FM", "583", "oceania"),
    ("FO", "234", "europe"),
    ("FR", "250", "europe"),
    ("GA", "266", "africa"),
    ("GB", "826", "europe"),
    ("GD", "308", "north-america"),
    ("GE", "268", "asia"),
    ("GF", "254", "south-america"),
    ("GG", "831", "europe"),
    ("GH", "288", "africa"),
    ("GI", "292", "europe"),
    ("GL", "304", "north-america"),
    ("GM", "270", "africa"),
    ("GN", "324", "africa"),
    ("GP", "312", "north-america"),
    ("GQ", "226", "africa"),
    ("GR", "300", "europe"),
    ("GS", "239", "south-america"),
    ("GT", "320", "north-america"),
    ("GU", "316", "oceania"),
    ("GW", "624", "africa"),
    ("GY", "328", "south-america"),
    ("HK", "344", "asia"),
    ("HM", "334", "oceania"),
    ("HN", "340", "north-america"),
    ("HR", "191", "europe"),
    ("HT", "332", "north-america"),
    ("HU", "348", "europe"),
    ("ID", "360", "asia"),
    ("IE", "372", "europe"),
    ("IL", "376", "asia"),
    ("IM", "833", "europe"),
    ("IN", "356", "asia"),
    ("IO", "086", "africa"),
    ("IQ", "368", "asia"),
    ("IR", "364", "asia"),
    ("IS", "352", "europe"),
    ("IT", "380", "europe"),
    ("JE", "832", "europe"),
    ("JM", "388", "north-america"),
    ("JO", "400", "asia"),
    ("JP", "392", "asia"),
    ("KE", "404", "africa"),
    ("KG", "417", "asia"),
    ("KH", "116", "asia"),
    ("KI", "296", "oceania"),
    ("KM", "174", "africa"),
    ("KN", "659", "north-america"),
    ("KP", "408", "asia"),
    ("KR", "410", "asia"),
    ("KW", "414", "asia"),
    ("KY", "136", "north-america"),
    ("KZ", "398", "asia"),
    ("LA", "418", "asia"),
    ("LB", "422", "asia"),
    ("LC", "662", "north-america"),
    ("LI", "438", "europe"),
    ("LK", "144", "asia"),
    ("LR", "430", "africa"),
    ("LS", "426", "africa"),
    ("LT", "440", "europe"),
    ("LU", "442", "europe"),
    ("LV", "428", "europe"),
    ("LY", "434", "africa"),
    ("MA", "504", "africa"),
    ("MC", "492", "europe"),
    ("MD", "498", "europe"),
    ("ME", "499", "europe"),
    ("MF", "663", "north-america"),
    ("MG", "450", "africa"),
    ("MH", "584", "oceania"),
    ("MK", "807", "europe"),
    ("ML", "466", "africa"),
    ("MM", "104", "asia"),
    ("MN", "496", "asia"),
    ("MO", "446", "asia"),
    ("MP", "580", "oceania"),
    ("MQ", "474", "north-america"),
    ("MR", "478", "africa"),
    ("MS", "500", "north-america"),
    ("MT", "470", "europe"),
    ("MU", "480", "africa"),
    ("MV", "462", "asia"),
    ("MW", "454", "africa"),
    ("MX", "484", "north-america"),
    ("MY", "458", "asia"),
    ("MZ", "508", "africa"),
    ("NA", "516", "africa"),
    ("NC", "540", "oceania"),
    ("NE", "562", "africa"),
    ("NF", "574", "oceania"),
    ("NG", "566", "africa"),
    ("NI", "558", "north-america"),
    ("NL", "528", "europe"),
    ("NO", "578", "europe"),
    ("NP", "524", "asia"),
    ("NR", "520", "oceania"),
    ("NU", "570", "oceania"),
    ("NZ", "554", "oceania"),
    ("OM", "512", "asia"),
    ("PA", "591", "north-america"),
    ("PE", "604", "south-america"),
    ("PF", "258", "oceania"),
    ("PG", "598", "oceania"),
    ("PH", "608", "asia"),
    ("PK", "586", "asia"),
    ("PL", "616", "europe"),
    ("PM", "666", "north-america"),
    ("PN", "612", "oceania"),
    ("PR", "630", "north-america"),
    ("PS", "275", "asia"),
    ("PT", "620", "europe"),
    ("PW", "585", "oceania"),
    ("PY", "600", "south-america"),
    ("QA", "634", "asia"),
    ("RE", "638", "africa"),
    ("RO", "642", "europe"),
    ("RS", "688", "europe"),
    ("RU", "643", "europe"),
    ("RW", "646", "africa"),
    ("SA", "682", "asia"),
    ("SB", "090", "oceania"),
    ("SC", "690", "africa"),
    ("SD", "729", "africa"),
    ("SE", "752", "europe"),
    ("SG", "702", "asia"),
    ("SH", "654", "africa"),
    ("SI", "705", "europe"),
    ("SJ", "744", "europe"),
    ("SK", "703", "europe"),
    ("SL", "694", "africa"),
    ("SM", "674", "europe"),
    ("SN", "686", "africa"),
    ("SO", "706", "africa"),
    ("SR", "740", "south-america"),
    ("SS", "728", "africa"),
    ("ST", "678", "africa"),
    ("SV", "222", "north-america"),
    ("SX", "534", "north-america"),
    ("SY", "760", "asia"),
    ("SZ", "748", "africa"),
    ("TC", "796", "north-america"),
    ("TD", "148", "africa"),
    ("TF", "260", "africa"),
    ("TG", "768", "africa"),
    ("TH", "764", "asia"),
    ("TJ", "762", "asia"),
    ("TK", "772", "oceania"),
    ("TL", "626", "asia"),
    ("TM", "795", "asia"),
    ("TN", "788", "africa"),
    ("TO", "776", "oceania"),
    ("TR", "792", "asia"),
    ("TT", "780", "north-america"),
    ("TV", "798", "oceania"),
    ("TZ", "834", "africa"),
    ("UA", "804", "europe"),
    ("UG", "800", "africa"),
    ("UM", "581", "oceania"),
    ("US", "840", "north-america"),
    ("UY", "858", "south-america"),
    ("UZ", "860", "asia"),
    ("VA", "336", "europe"),
    ("VC", "670", "north-america"),
    ("VE", "862", "south-america"),
    ("VG", "092", "north-america"),
    ("VI", "850", "north-america"),
    ("VN", "704", "asia"),
    ("VU", "548", "oceania"),
    ("WF", "876", "oceania"),
    ("WS", "882", "oceania"),
    ("YE", "887", "asia"),
    ("YT", "175", "africa"),
    ("ZA", "710", "africa"),
    ("ZM", "894", "africa"),
    ("ZW", "716", "africa"),
];

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

    let summary = format!(
        "vendored snapshot `{relative}` (complete {}-row country->m49+region pin; {MINIMUM_DATA_ROWS}+ row floor)",
        EXPECTED_M49_COUNTRIES.len()
    );
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

    let mut seen: BTreeMap<String, (String, String)> = BTreeMap::new();
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
        if seen
            .insert(iso.to_string(), (m49_code.to_string(), region.to_string()))
            .is_some()
        {
            outcome
                .violations
                .push(format!("row {row}: duplicate ISO code `{iso}`"));
        }
        if let Some(previous) = &previous_iso
            && previous.as_str() >= iso
        {
            outcome.violations.push(format!(
                "row {row}: rows must be sorted ascending by ISO code (`{iso}` follows `{previous}`)"
            ));
        }
        previous_iso = Some(iso.to_string());
        if let Some(expected) = expected_region
            && region != expected.as_str()
        {
            outcome.violations.push(format!(
                "row {row}: region `{region}` does not match m49_region_code `{code}` (expected `{expected}`)"
            ));
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

    // WO-W7: set equality against the canonical country set. The row
    // floor above passes a truncated snapshot (200 of 247 rows); every
    // missing country — and every code outside the set — is a named
    // violation.
    let expected: BTreeSet<&str> = EXPECTED_M49_COUNTRIES
        .iter()
        .map(|(iso, _, _)| *iso)
        .collect();
    let actual: BTreeSet<&str> = seen.keys().map(String::as_str).collect();
    for code in expected.difference(&actual) {
        outcome
            .violations
            .push(format!("canonical ISO code `{code}` is missing"));
    }
    for code in actual.difference(&expected) {
        outcome.violations.push(format!(
            "ISO code `{code}` is not part of the canonical 247-code country set"
        ));
    }

    // Round-8 X1: set equality pinned the ISO codes only, so a country's
    // own mapping could drift — GB's region moved to asia (with the
    // taxonomy-consistent 142) and its m49_code changed outright, both
    // without a single violation. Each canonical country's full mapping
    // is now pinned: m49_code and region must match row-for-row.
    for (iso, pinned_m49, pinned_region) in EXPECTED_M49_COUNTRIES {
        let Some((m49_code, region)) = seen.get(iso) else {
            continue; // already a named missing-code violation above
        };
        if m49_code != pinned_m49 {
            outcome.violations.push(format!(
                "ISO `{iso}` m49_code must be `{pinned_m49}`, got `{m49_code}`"
            ));
        }
        if region != pinned_region {
            outcome.violations.push(format!(
                "ISO `{iso}` region must be `{pinned_region}`, got `{region}`"
            ));
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

    /// pr-champion round-6 triage, WO-W7: completeness was a 150-row
    /// FLOOR against a 247-row canonical file, so a snapshot that dropped
    /// 47 countries still passed m49-verify. The exact ISO-alpha-2 set is
    /// pinned: any missing country is a named violation, and a code
    /// outside the set is one too.
    #[test]
    fn incomplete_country_set_fails() {
        // 200 of the 247 canonical codes, every row individually valid:
        // the pre-existing 150-row floor passes 200 rows, so only the set
        // pin can notice the 47 missing countries.
        let mut rows = String::new();
        for (code, _, _) in EXPECTED_M49_COUNTRIES.iter().take(200) {
            rows.push_str(&format!("002,004,{code},X,africa\n"));
        }
        let csv = format!("{CSV_HEADER}\n{rows}");
        let outcome = verify_csv(csv.as_bytes(), &mapping());
        assert!(
            outcome
                .violations
                .iter()
                .any(|v| { v.contains("is missing") && v.contains(EXPECTED_M49_COUNTRIES[200].0) }),
            "the violation must name `{}` (the first missing code)",
            EXPECTED_M49_COUNTRIES[200].0
        );
    }

    /// The symmetric drift: a 248th row whose code the canonical set
    /// never contained. `ZZ` sorts after the last canonical code (`ZW`),
    /// so every other row-level rule stays satisfied.
    #[test]
    fn code_outside_the_canonical_set_fails() {
        let mut rows = String::new();
        for (code, _, _) in EXPECTED_M49_COUNTRIES {
            rows.push_str(&format!("002,004,{code},X,africa\n"));
        }
        rows.push_str("002,004,ZZ,Atlantis,africa\n");
        let csv = format!("{CSV_HEADER}\n{rows}");
        let outcome = verify_csv(csv.as_bytes(), &mapping());
        assert!(
            outcome
                .violations
                .iter()
                .any(|v| v.contains("`ZZ` is not part of the canonical")),
            "a code outside the 247-code set must be a named violation"
        );
    }

    /// The pin itself is pinned (the canonical_ids meta-test style): 247
    /// unique two-letter codes — the country/territory count the vendored
    /// snapshot carries — each with a 3-digit m49_code and a region inside
    /// the six-continent vocabulary, in the distribution the vendored
    /// snapshot documents (africa 60, asia 50, europe 51,
    /// north-america 41, south-america 16, oceania 29).
    #[test]
    fn canonical_country_pin_is_pinned() {
        let mut regions: BTreeMap<&str, usize> = BTreeMap::new();
        for (code, m49, region) in EXPECTED_M49_COUNTRIES {
            assert_eq!(code.len(), 2, "`{code}` must be two letters");
            assert!(
                code.bytes().all(|b| b.is_ascii_uppercase()),
                "`{code}` must be uppercase"
            );
            assert_eq!(m49.len(), 3, "`{code}`: m49_code `{m49}` must be 3 digits");
            assert!(
                m49.bytes().all(|b| b.is_ascii_digit()),
                "`{code}`: m49_code `{m49}` must be 3 digits"
            );
            assert!(
                [
                    "africa",
                    "asia",
                    "europe",
                    "north-america",
                    "south-america",
                    "oceania"
                ]
                .contains(&region),
                "`{code}`: region `{region}` is outside the six-continent vocabulary"
            );
            *regions.entry(region).or_default() += 1;
        }
        let unique: BTreeSet<&str> = EXPECTED_M49_COUNTRIES
            .iter()
            .map(|(code, _, _)| *code)
            .collect();
        assert_eq!(
            unique.len(),
            247,
            "the pinned set must contain exactly 247 unique codes"
        );
        assert_eq!(regions.get("africa"), Some(&60));
        assert_eq!(regions.get("asia"), Some(&50));
        assert_eq!(regions.get("europe"), Some(&51));
        assert_eq!(regions.get("north-america"), Some(&41));
        assert_eq!(regions.get("south-america"), Some(&16));
        assert_eq!(regions.get("oceania"), Some(&29));
    }

    /// Round-8 X1: the WO-W7 ISO set pin left each row's own mapping
    /// unconstrained — GB's region could move to asia (with the
    /// taxonomy-consistent 142, every row rule and the set pin stay
    /// satisfied), and its m49_code could change outright. The fixture
    /// carries all 247 canonical rows built from the pin itself (so the
    /// row floor, per-region counts, and set equality all pass); only the
    /// per-country mapping pin can name GB's drift.
    #[test]
    fn country_mapping_drift_for_one_country_fails() {
        let taxonomy = mapping();
        let code_for_region: BTreeMap<&str, &str> = taxonomy
            .iter()
            .map(|(code, region)| (region.as_str(), code.as_str()))
            .collect();
        for (label, gb_row, expected) in [
            (
                "region drift (taxonomy-consistent)",
                "142,826,GB,X,asia\n",
                "ISO `GB` region must be `europe`, got `asia`",
            ),
            (
                "m49_code drift",
                "150,082,GB,X,europe\n",
                "ISO `GB` m49_code must be `826`, got `082`",
            ),
        ] {
            let mut rows = String::new();
            for (iso, m49, region) in EXPECTED_M49_COUNTRIES {
                if iso == "GB" {
                    rows.push_str(gb_row);
                } else {
                    let code = code_for_region
                        .get(region)
                        .copied()
                        .expect("the six-continent fixture taxonomy covers every region");
                    rows.push_str(&format!("{code},{m49},{iso},X,{region}\n"));
                }
            }
            let csv = format!("{CSV_HEADER}\n{rows}");
            let outcome = verify_csv(csv.as_bytes(), &mapping());
            assert!(
                outcome.violations.iter().any(|v| v.contains(expected)),
                "{label}: the violation must be `{expected}`, got {:?}",
                outcome.violations
            );
        }
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
