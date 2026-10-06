//! The ProtonWire routing-table plan (FR-34, IT-25): WHICH table IDs
//! the daemon owns, decided BEFORE any netlink write touches the host.
//!
//! 51820/51821/51822 (`protonwire-main`/`-bypass`/`-lan`) are
//! PREFERRED ids, never unconditional constants: startup inspects
//! `/etc/iproute2/rt_tables` and the active rules/routes, reuses only
//! a table PROVEN ProtonWire-owned, otherwise allocates conflict-free
//! ids and persists the mapping. A table whose numeric id merely
//! matches a preferred value is a LOOKALIKE — never reused, never
//! flushed (the crash-cleanup bar IT-25 pins).
//!
//! Ownership evidence is the daemon's PRIVATE persisted mapping
//! (a state file only ProtonWire writes): a matching rt_tables name
//! corroborates but cannot prove (names are forgeable), a DIFFERENT
//! name at a persisted id contradicts (another manager squatted the
//! stale record — allocate elsewhere). The survey's `occupied` set
//! does NOT contradict a persisted id: after a crash our own stale
//! rules still reference it, and cleanup — not the planner — owns
//! removing them.
//!
//! Pure decision logic: the netlink reader (live rules/routes) and
//! writer (rules, routes, names) are the next slice's seams.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Kernel-reserved routing-table ids (`unspec`, `default`, `main`,
/// `local`); the whole sub-256 range is iproute2-managed and never
/// allocated.
const KERNEL_RESERVED_MAX: u32 = 255;

/// The three ProtonWire tables, one per policy lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    /// The tunnel's own routes (full-tunnel default routes live here).
    Main,
    /// Split-tunnel bypass routes.
    Bypass,
    /// LAN access routes (FR-36).
    Lan,
}

impl TableKind {
    /// Every kind, in plan order (main first — later kinds' allocation
    /// skips earlier kinds' resolved ids).
    pub const ALL: [TableKind; 3] = [TableKind::Main, TableKind::Bypass, TableKind::Lan];

    /// The PRD's recommended id — preferred, never guaranteed.
    pub fn preferred_id(self) -> u32 {
        match self {
            TableKind::Main => 51820,
            TableKind::Bypass => 51821,
            TableKind::Lan => 51822,
        }
    }

    /// The canonical rt_tables name for this kind.
    pub fn canonical_name(self) -> &'static str {
        match self {
            TableKind::Main => "protonwire-main",
            TableKind::Bypass => "protonwire-bypass",
            TableKind::Lan => "protonwire-lan",
        }
    }
}

/// How a planned table id was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// The PRD's preferred id, free of any name or use.
    Preferred,
    /// The daemon's own persisted mapping, uncontradicted.
    Persisted,
    /// A conflict-free id allocated above the preferred one.
    Allocated,
}

/// One resolved table: kind, id, and how the id was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableAssignment {
    pub kind: TableKind,
    pub id: u32,
    pub provenance: Provenance,
}

/// The resolved set: which table ids ProtonWire owns this run. This
/// IS the ownership evidence every later stage checks against —
/// routes/rules on any id outside the plan are lookalikes and cleanup
/// must refuse them (IT-25).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TablePlan {
    assignments: Vec<TableAssignment>,
}

impl TablePlan {
    /// The assignment for one kind.
    pub fn assignment(&self, kind: TableKind) -> TableAssignment {
        self.assignments
            .iter()
            .find(|assignment| assignment.kind == kind)
            .copied()
            .expect("the plan carries one assignment per kind")
    }

    /// Every planned id.
    pub fn ids(&self) -> BTreeSet<u32> {
        self.assignments
            .iter()
            .map(|assignment| assignment.id)
            .collect()
    }

    /// Whether a table id is PROVEN ProtonWire-owned this run — the
    /// crash-cleanup gate: state on any other id is a lookalike.
    pub fn owns(&self, id: u32) -> bool {
        self.assignments
            .iter()
            .any(|assignment| assignment.id == id)
    }
}

/// The persisted mapping (the ownership record the daemon writes
/// under its state dir and only it writes). Serializable for the
/// store lane's state file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedTables {
    pub main: u32,
    pub bypass: u32,
    pub lan: u32,
}

impl PersistedTables {
    fn for_kind(&self, kind: TableKind) -> u32 {
        match kind {
            TableKind::Main => self.main,
            TableKind::Bypass => self.bypass,
            TableKind::Lan => self.lan,
        }
    }
}

/// Everything the planner needs to know about the host before
/// deciding: named tables (rt_tables), ids referenced by live
/// rules/routes (any owner), which of those carry OUR canonical
/// entry shapes (entry-level ownership proof), and the daemon's
/// persisted mapping.
#[derive(Debug, Clone, Default)]
pub struct TableSurvey {
    /// id → name, from `/etc/iproute2/rt_tables` ([`parse_rt_tables`]).
    pub named: BTreeMap<u32, String>,
    /// Ids referenced by active policy rules or routes — owner
    /// unknown from netlink alone.
    pub occupied: BTreeSet<u32>,
    /// The subset of `occupied` whose referencing entries PROVE
    /// ProtonWire's canonical shapes (the executor's entry-level
    /// check: priority band, from-all, our rule/route shapes). The
    /// ONLY occupied ids a persisted record may reclaim — occupied
    /// without proof could be a foreign squatter on our stale id
    /// (the round-3 P1), and reclaiming would mix FR-34's lanes.
    pub occupied_by_us: BTreeSet<u32>,
    /// The previous run's mapping, if the state file exists.
    pub persisted: Option<PersistedTables>,
}

/// Parse `/etc/iproute2/rt_tables` content: `#` comments, blank
/// lines, `<id> <name>` entries; later entries override earlier ones
/// with the same id (iproute2's behavior); anything else is skipped.
/// IDs parse BASE-AWARE like iproute2 itself (`fread_id_name`):
/// `0xca6c` is as valid as `51820` — a decimal-only parse would read
/// a hex-named table as absent and claim its id (the round-1 P1).
pub fn parse_rt_tables(text: &str) -> BTreeMap<u32, String> {
    let mut named = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((id, name)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        // Radix-aware like iproute2 strtoul-base-0 (fread_id_name):
        // 0x hex, legacy-0 octal, 0b binary, else decimal — Rust has
        // no radix-0, so spelled out.
        let Ok(id) = parse_rt_tables_id(id.trim()) else {
            continue;
        };
        // ONE name token (the round-3 P2): iproute2 reads the first
        // whitespace-delimited token and ignores trailing commentary
        // (`51820 protonwire-main # managed locally`); our whole-rest
        // read rejected such lines as absent — claiming the id.
        let Some(name) = name.trim().split_whitespace().next() else {
            continue;
        };
        if name.starts_with('#') {
            continue;
        }
        named.insert(id, name.to_owned());
    }
    named
}

/// iproute2's base-aware rt_tables id: `0x` hex, a leading zero
/// (beyond a lone `0`) octal, `0b` binary, else decimal — strtoul
/// with base 0, as `fread_id_name` reads the file.
fn parse_rt_tables_id(text: &str) -> Result<u32, std::num::ParseIntError> {
    let (digits, radix) =
        if let Some(rest) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (rest, 16)
        } else if let Some(rest) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
            (rest, 2)
        } else if text.len() > 1
            && text.starts_with('0')
            && text[1..].bytes().all(|byte| byte.is_ascii_digit())
        {
            (&text[1..], 8)
        } else {
            (text, 10)
        };
    u32::from_str_radix(digits, radix)
}

/// Decide the plan: per kind — the persisted id unless contradicted
/// by a foreign name, else the preferred id if free, else the first
/// conflict-free id above it. Never mutates, never flushes; the
/// writer owns applying (and naming) what this returns.
pub fn plan_tables(survey: &TableSurvey) -> TablePlan {
    let mut claimed = BTreeSet::new();
    let mut assignments = Vec::new();
    for kind in TableKind::ALL {
        let assignment = resolve(kind, survey, &claimed);
        claimed.insert(assignment.id);
        assignments.push(assignment);
    }
    TablePlan { assignments }
}

/// One kind's resolution: persisted (uncontradicted AND valid) →
/// preferred (free) → first free id above the preferred one.
fn resolve(kind: TableKind, survey: &TableSurvey, claimed: &BTreeSet<u32>) -> TableAssignment {
    if let Some(persisted) = &survey.persisted {
        let id = persisted.for_kind(kind);
        // OCCUPIED state demands entry-level proof (the round-3 P1):
        // a persisted id referenced by live rules/routes is ours only
        // when the entries PROVE it — the survey's occupied_by_us
        // (the executor's canonical-shape check) or a corroborating
        // rt_tables name. The bare private record plus unproven
        // occupation could be a foreign squatter on our stale id:
        // reclaiming would mix FR-34's lanes and strand the plan's
        // ownership gate. OUR crash residue passes the shape check,
        // so a genuine restart still reclaims (nothing strips a
        // clean restart's id).
        let occupied = survey.occupied.contains(&id);
        let proven_ours = survey.occupied_by_us.contains(&id)
            || survey
                .named
                .get(&id)
                .is_some_and(|name| name == kind.canonical_name());
        let contradicted = survey
            .named
            .get(&id)
            .is_some_and(|name| name != kind.canonical_name());
        // A syntactically valid state file can still hold a CORRUPT
        // record: a kernel-reserved id (e.g. `main: 254`), an id the
        // record assigns to a SIBLING lane too (ambiguous — only the
        // colliding lanes distrust it; a distinct sibling entry is
        // still evidence), or an id another lane already resolved to
        // this run — none of that is ownership evidence (the round-1
        // P2). Reject and fall through to allocation.
        let collides_with_sibling = TableKind::ALL
            .iter()
            .any(|other| *other != kind && persisted.for_kind(*other) == id);
        let valid = id > KERNEL_RESERVED_MAX && !collides_with_sibling && !claimed.contains(&id);
        if !contradicted && valid && (!occupied || proven_ours) {
            return TableAssignment {
                kind,
                id,
                provenance: Provenance::Persisted,
            };
        }
    }
    let preferred = kind.preferred_id();
    let id = if claimable(preferred, survey, claimed) {
        preferred
    } else {
        let mut candidate = preferred + 1;
        while !free(candidate, survey, claimed) {
            candidate += 1;
        }
        candidate
    };
    TableAssignment {
        kind,
        id,
        provenance: if id == preferred {
            Provenance::Preferred
        } else {
            Provenance::Allocated
        },
    }
}

/// Whether an id can be CLAIMED: un-named, un-used, not already
/// claimed in this plan, and outside the kernel's range. The
/// preferred-id path uses this directly — a kind's own preferred id
/// is claimable when genuinely free.
fn claimable(id: u32, survey: &TableSurvey, claimed: &BTreeSet<u32>) -> bool {
    id > KERNEL_RESERVED_MAX
        && !survey.named.contains_key(&id)
        && !survey.occupied.contains(&id)
        && !claimed.contains(&id)
}

/// Whether an id is free for an ALLOCATED claim: claimable AND
/// outside the whole preferred set — the set is honored as a unit
/// (the id↔name correspondence a human reads in `ip rule`), so a
/// displaced kind lands above all three ids, never inside a
/// sibling's slot.
fn free(id: u32, survey: &TableSurvey, claimed: &BTreeSet<u32>) -> bool {
    claimable(id, survey, claimed) && !TableKind::ALL.iter().any(|kind| kind.preferred_id() == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn survey(
        named: &[(u32, &str)],
        occupied: &[u32],
        persisted: Option<PersistedTables>,
    ) -> TableSurvey {
        TableSurvey {
            named: named
                .iter()
                .map(|(id, name)| (*id, (*name).to_owned()))
                .collect(),
            occupied: occupied.iter().copied().collect(),
            occupied_by_us: BTreeSet::new(),
            persisted,
        }
    }

    #[test]
    fn parse_rt_tables_handles_comments_blanks_and_overrides() {
        let text = "\
# reserved values
255\tlocal
254\tmain
253\tdefault
0\tunspec

# local
#
51820  protonwire-main
51820  redefined-later
not-an-entry
  51821\tprotonwire-bypass
";
        let parsed = parse_rt_tables(text);
        assert_eq!(parsed.len(), 6);
        assert_eq!(parsed[&255], "local");
        assert_eq!(
            parsed[&51820], "redefined-later",
            "later entries override earlier ones, iproute2's behavior"
        );
        assert_eq!(parsed[&51821], "protonwire-bypass");
        assert!(!parsed.contains_key(&5182));
    }

    #[test]
    fn preferred_ids_taken_on_an_idle_host() {
        let plan = plan_tables(&survey(&[], &[], None));
        assert_eq!(
            plan.assignment(TableKind::Main),
            TableAssignment {
                kind: TableKind::Main,
                id: 51820,
                provenance: Provenance::Preferred
            }
        );
        assert_eq!(plan.assignment(TableKind::Bypass).id, 51821);
        assert_eq!(plan.assignment(TableKind::Lan).id, 51822);
    }

    #[test]
    fn occupied_preferred_id_allocates_conflict_free_per_kind() {
        // IT-25: a preferred id conflict allocates a different table.
        // 51820 is named by ANOTHER manager; 51822 is referenced by
        // live rules with no name at all.
        let plan = plan_tables(&survey(&[(51820, "corp-vpn")], &[51822], None));
        let main = plan.assignment(TableKind::Main);
        assert_eq!(main.id, 51823, "the first id above the preferred one");
        assert_eq!(main.provenance, Provenance::Allocated);
        // The OTHER kinds keep their own preferred ids — allocation
        // is per kind, not all-or-nothing.
        assert_eq!(plan.assignment(TableKind::Bypass).id, 51821);
        assert_eq!(
            plan.assignment(TableKind::Lan),
            TableAssignment {
                kind: TableKind::Lan,
                id: 51823 + 1,
                provenance: Provenance::Allocated
            }
        );
        // And the foreign 51820 is outside the plan — a lookalike.
        assert!(!plan.owns(51820));
        assert!(!plan.owns(51822));
    }

    #[test]
    fn persisted_mapping_is_reused_when_our_shapes_occupy_it() {
        let persisted = PersistedTables {
            main: 53000,
            bypass: 51821,
            lan: 53002,
        };
        // No rt_tables names (the daemon never names tables), and
        // 53000 is rule-occupied by OUR canonical shapes — after our
        // own crash our stale rules still reference it, and the
        // entry-level proof (occupied_by_us) keeps it reclaimable.
        let mut our_crash = survey(&[], &[53000], Some(persisted.clone()));
        our_crash.occupied_by_us.insert(53000);
        let plan = plan_tables(&our_crash);
        assert_eq!(
            plan.assignment(TableKind::Main),
            TableAssignment {
                kind: TableKind::Main,
                id: 53000,
                provenance: Provenance::Persisted
            }
        );
        assert_eq!(plan.assignment(TableKind::Bypass).id, 51821);
        assert_eq!(plan.assignment(TableKind::Lan).id, 53002);
        assert!(plan.owns(53000));
    }

    #[test]
    fn squatted_occupation_without_entry_proof_is_not_reclaimed() {
        // The round-3 P1: another manager took our stale id while we
        // were stopped — the persisted record alone must not reclaim
        // an id their (unproven) rules occupy; allocate elsewhere.
        let persisted = PersistedTables {
            main: 53000,
            bypass: 53001,
            lan: 53002,
        };
        let plan = plan_tables(&survey(&[], &[53000], Some(persisted)));
        assert_eq!(
            plan.assignment(TableKind::Main).provenance,
            Provenance::Preferred,
            "unproven occupation pushes to a fresh id — never mix lanes"
        );
        assert!(!plan.owns(53000));
        // A corroborating canonical NAME is entry-level proof too.
        let persisted = PersistedTables {
            main: 53000,
            bypass: 53001,
            lan: 53002,
        };
        let plan = plan_tables(&survey(
            &[(53000, "protonwire-main")],
            &[53000],
            Some(persisted),
        ));
        assert_eq!(
            plan.assignment(TableKind::Main).provenance,
            Provenance::Persisted
        );
    }

    #[test]
    fn rt_tables_names_read_one_token_with_trailing_comment() {
        // The round-3 P2: the whole-rest read rejected this valid
        // iproute2 line (name would carry the comment) — the id read
        // as absent and the planner could claim it.
        let named = parse_rt_tables("51820 protonwire-main # managed locally\n");
        assert_eq!(named[&51820], "protonwire-main");
        // The canonical name now matches — a persisted+occupied id
        // with this line is name-proven.
        let persisted = PersistedTables {
            main: 51820,
            bypass: 51821,
            lan: 51822,
        };
        let plan = plan_tables(&survey(
            &[(51820, "protonwire-main")],
            &[51820],
            Some(persisted),
        ));
        assert_eq!(
            plan.assignment(TableKind::Main).provenance,
            Provenance::Persisted
        );
    }

    #[test]
    fn octal_ids_parse_like_iproute2() {
        assert_eq!(parse_rt_tables("0620 legacy-octal\n")[&400], "legacy-octal");
    }

    #[test]
    fn plan_invariants_hold_under_sweeps() {
        // The brute-force pin (rust-review #10): across named/occupied
        // combinations the plan's invariants never bend — ids unique,
        // outside the kernel range, never foreign-named, allocations
        // outside the preferred set.
        let mut named = std::collections::BTreeMap::new();
        named.insert(51820_u32, "someone-else".to_owned());
        named.insert(51821_u32, "protonwire-bypass".to_owned());
        for occupied_extra in [0_u32, 51822, 51823, 51824] {
            let mut occupied = std::collections::BTreeSet::from([51820, 51821]);
            if occupied_extra != 0 {
                occupied.insert(occupied_extra);
            }
            let plan = plan_tables(&TableSurvey {
                named: named.clone(),
                occupied: occupied.clone(),
                occupied_by_us: Default::default(),
                persisted: None,
            });
            let ids: Vec<_> = TableKind::ALL.map(|kind| plan.assignment(kind).id).to_vec();
            for id in &ids {
                assert!(*id > 255);
                assert_ne!(named.get(id).map(String::as_str), Some("someone-else"));
                assert!(!occupied.contains(id) || *id == 51821);
            }
            let mut unique = ids.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(unique.len(), ids.len(), "ids unique: {ids:?}");
            for kind in TableKind::ALL {
                let assignment = plan.assignment(kind);
                if assignment.provenance == Provenance::Allocated {
                    assert!(assignment.id > 51822);
                }
            }
        }
    }

    #[test]
    fn foreign_name_at_a_persisted_id_contradicts_and_reallocates() {
        let persisted = PersistedTables {
            main: 53000,
            bypass: 53001,
            lan: 53002,
        };
        // Another manager squatted our stale record's id AND the
        // preferred one: neither is reusable.
        let plan = plan_tables(&survey(
            &[(53000, "someone-else"), (51820, "also-someone-else")],
            &[],
            Some(persisted),
        ));
        let main = plan.assignment(TableKind::Main);
        assert_eq!(
            main.id, 51823,
            "past both the contradicted record and the taken preferred"
        );
        assert_eq!(main.provenance, Provenance::Allocated);
        assert!(!plan.owns(53000), "the squatted record is a lookalike now");
        // Bypass/Lan persisted ids were uncontradicted: still reused.
        assert_eq!(plan.assignment(TableKind::Bypass).id, 53001);
        assert_eq!(plan.assignment(TableKind::Lan).id, 53002);
    }

    #[test]
    fn a_matching_name_alone_proves_nothing_without_the_record() {
        // IT-25's lookalike bar: rt_tables NAMING a table
        // "protonwire-main" without our persisted record is not
        // ownership evidence — names are forgeable. The preferred id
        // is named (by whoever), so the planner must allocate
        // elsewhere and never claim it.
        let plan = plan_tables(&survey(&[(51820, "protonwire-main")], &[], None));
        assert!(!plan.owns(51820));
        assert_eq!(plan.assignment(TableKind::Main).id, 51823);
        assert_eq!(
            plan.assignment(TableKind::Main).provenance,
            Provenance::Allocated
        );
    }

    #[test]
    fn allocation_skips_kernel_reserved_and_names_in_its_scan() {
        // Squeeze the scan: everything from 51821 up through the
        // named/occupied ids is taken, so Lan lands above them all.
        let named: Vec<(u32, &str)> = (51821..=51829)
            .map(|id| (id, "taken"))
            .chain([(51830u32, "taken")])
            .collect();
        let occupied: Vec<u32> = vec![51820, 51831];
        let plan = plan_tables(&survey(&named, &occupied, None));
        assert_eq!(plan.assignment(TableKind::Main).id, 51832);
        assert_eq!(plan.assignment(TableKind::Bypass).id, 51833);
        assert_eq!(plan.assignment(TableKind::Lan).id, 51834);
    }

    #[test]
    fn hex_ids_parse_like_iproute2() {
        // The round-1 P1: iproute2 accepts 0x-prefixed ids — a
        // decimal-only parse read this table as absent and claimed
        // its id (0xca6c == 51820).
        let named = parse_rt_tables("0xca6c  corp-vpn\n0x101  also-hex\n");
        assert_eq!(named[&51820], "corp-vpn");
        assert_eq!(named[&257], "also-hex");
        let plan = plan_tables(&survey(&[(51820, "corp-vpn")], &[], None));
        assert!(
            !plan.owns(51820),
            "the hex-named foreign table is never claimed"
        );
    }

    #[test]
    fn corrupt_persisted_records_fall_back_to_allocation() {
        // The round-1 P2: reserved ids and duplicate lanes in a
        // syntactically valid state file are not ownership.
        let reserved = PersistedTables {
            main: 254,
            bypass: 51821,
            lan: 51822,
        };
        let plan = plan_tables(&survey(&[], &[], Some(reserved)));
        assert_eq!(
            plan.assignment(TableKind::Main).provenance,
            Provenance::Preferred,
            "the reserved record is rejected; the free preferred id is taken instead"
        );
        assert_eq!(plan.assignment(TableKind::Main).id, 51820);
        assert!(!plan.owns(254), "the kernel main table is never claimed");
        assert_eq!(
            plan.assignment(TableKind::Bypass).provenance,
            Provenance::Persisted
        );

        let duplicate = PersistedTables {
            main: 53000,
            bypass: 53000,
            lan: 53002,
        };
        let plan = plan_tables(&survey(&[], &[], Some(duplicate)));
        // The record is ambiguous for BOTH duplicate lanes — neither
        // can prove which one owns 53000, so neither trusts it.
        assert_eq!(
            plan.assignment(TableKind::Main).provenance,
            Provenance::Preferred
        );
        assert_eq!(
            plan.assignment(TableKind::Bypass).provenance,
            Provenance::Preferred
        );
        assert!(!plan.owns(53000), "the ambiguous id is not claimed");
        assert_ne!(
            plan.assignment(TableKind::Bypass).id,
            plan.assignment(TableKind::Main).id
        );
        // The non-duplicate lane still trusts its record.
        assert_eq!(
            plan.assignment(TableKind::Lan).provenance,
            Provenance::Persisted
        );
    }

    #[test]
    fn persisted_tables_round_trip_through_serde() {
        let persisted = PersistedTables {
            main: 53000,
            bypass: 53001,
            lan: 53002,
        };
        let serialized = serde_json::to_string(&persisted).unwrap();
        assert_eq!(
            serde_json::from_str::<PersistedTables>(&serialized).unwrap(),
            persisted
        );
    }
}
