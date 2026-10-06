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
/// rules/routes (any owner), and the daemon's persisted mapping.
#[derive(Debug, Clone, Default)]
pub struct TableSurvey {
    /// id → name, from `/etc/iproute2/rt_tables` ([`parse_rt_tables`]).
    pub named: BTreeMap<u32, String>,
    /// Ids referenced by active policy rules or routes — owner
    /// unknown from netlink alone.
    pub occupied: BTreeSet<u32>,
    /// The previous run's mapping, if the state file exists.
    pub persisted: Option<PersistedTables>,
}

/// Parse `/etc/iproute2/rt_tables` content: `#` comments, blank
/// lines, `<id> <name>` entries; later entries override earlier ones
/// with the same id (iproute2's behavior); anything else is skipped.
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
        let Ok(id) = id.trim().parse::<u32>() else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name.starts_with('#') {
            continue;
        }
        named.insert(id, name.to_owned());
    }
    named
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

/// One kind's resolution: persisted (uncontradicted) → preferred
/// (free) → first free id above the preferred one.
fn resolve(kind: TableKind, survey: &TableSurvey, claimed: &BTreeSet<u32>) -> TableAssignment {
    if let Some(persisted) = &survey.persisted {
        let id = persisted.for_kind(kind);
        let contradicted = survey
            .named
            .get(&id)
            .is_some_and(|name| name != kind.canonical_name());
        if !contradicted {
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
    fn persisted_mapping_is_reused_when_uncontradicted() {
        let persisted = PersistedTables {
            main: 53000,
            bypass: 51821,
            lan: 53002,
        };
        // No rt_tables names at all (the daemon never names tables),
        // and 53000 is even rule-occupied — after OUR crash our own
        // stale rules still reference it; that is not a contradiction.
        let plan = plan_tables(&survey(&[], &[53000], Some(persisted.clone())));
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
