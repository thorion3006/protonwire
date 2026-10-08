//! The transactional netlink writer (FR-33/38, M5 slice 2): batches
//! of route/rule operations applied in order with ROLLBACK of the
//! applied prefix on failure — FR-38's "transactional where possible"
//! for a netlink surface that acks per message.
//!
//! Every operation is built against a [`crate::tables::TablePlan`]
//! and REFUSED at construction when its table is outside the plan —
//! a route or rule on any other id is a lookalike (IT-25's cleanup
//! bar, wired into the writer itself, not just the cleanup pass).
//!
//! The transactional core ([`crate::route_txn::RouteTransaction::apply`], rollback
//! ordering, the lookalike refusal) is pure logic over the async
//! [`crate::route_txn::NetlinkExecutor`] trait; [`crate::route_txn::RtnetlinkExecutor`] is the live
//! implementation whose kernel behavior the netns IT pins
//! (`it_route_transactions`). The executor's caller owns the async
//! runtime — the daemon's slice later decides sync-wrap or task.

use std::collections::BTreeSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures_util::StreamExt;

use crate::tables::{TablePlan, TableSurvey, plan_tables};

/// What a policy rule DOES with matched traffic. ToTable is the
/// tunnel/bypass shape; Blackhole is routing-level blocking (FR-37:
/// v6 enforcement independent of the kill switch — the round-3 P1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    ToTable,
    Blackhole,
}

/// Which address family a rule speaks — rules are family-scoped in
/// the kernel (a v4 rule never steers v6 packets, and vice versa),
/// so the desired state carries one rule per family it tunnels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// The netlink rule-dump filter for this family.
    fn ip_version(self) -> rtnetlink::IpVersion {
        match self {
            Family::V4 => rtnetlink::IpVersion::V4,
            Family::V6 => rtnetlink::IpVersion::V6,
        }
    }
}

/// What a policy rule DOES with matched traffic. ToTable is the
/// One policy rule: everything ProtonWire puts in a rule, everything
/// the writer needs to find and remove it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSpec {
    /// The plan-owned table the rule routes into (0 for Blackhole —
    /// a block has no destination table).
    pub table: u32,
    /// Rule priority (lower wins; ProtonWire uses a fixed band).
    pub priority: u32,
    /// The fwmark the rule matches, if any.
    pub fwmark: Option<u32>,
    /// The family the rule steers.
    pub family: Family,
    /// What the rule does.
    pub action: RuleKind,
}

/// A destination prefix, family carried by the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestPrefix {
    pub addr: IpAddr,
    pub len: u8,
}

impl DestPrefix {
    /// The IPv4 default route.
    pub const V4_DEFAULT: DestPrefix = DestPrefix {
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        len: 0,
    };
    /// The IPv6 default route.
    pub const V6_DEFAULT: DestPrefix = DestPrefix {
        addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        len: 0,
    };
}

/// One route: table, destination, output interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSpec {
    /// The plan-owned table the route lives in.
    pub table: u32,
    /// Destination prefix (`0.0.0.0/0` for a default route).
    pub dest: DestPrefix,
    /// Output interface index.
    pub oif: u32,
}

/// One batched netlink operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetOp {
    AddRule(RuleSpec),
    DelRule(RuleSpec),
    AddRoute(RouteSpec),
    DelRoute(RouteSpec),
}

impl NetOp {
    /// The table this operation touches (every op is table-scoped).
    pub fn table(self) -> u32 {
        match self {
            NetOp::AddRule(spec) | NetOp::DelRule(spec) => spec.table,
            NetOp::AddRoute(spec) | NetOp::DelRoute(spec) => spec.table,
        }
    }
}

/// The inverse operation — what rollback replays: adds undo to
/// deletes and vice versa.
pub fn inverse(op: NetOp) -> NetOp {
    match op {
        NetOp::AddRule(spec) => NetOp::DelRule(spec),
        NetOp::DelRule(spec) => NetOp::AddRule(spec),
        NetOp::AddRoute(spec) => NetOp::DelRoute(spec),
        NetOp::DelRoute(spec) => NetOp::AddRoute(spec),
    }
}

/// What an executor reports for one operation.
pub type NetOpError = String;

/// The kernel surface a transaction runs against. The fake in the
/// tests records and fails on demand; [`crate::route_txn::RtnetlinkExecutor`] speaks
/// real netlink. Send-bounded RPIT (not `async fn`): the future must
/// travel across the daemon's runtime; the CALLER owns the runtime.
pub trait NetlinkExecutor {
    /// Apply one operation; the flag reports whether KERNEL STATE
    /// CHANGED. Adds are IDEMPOTENT (an already-present spec is a
    /// no-op — Linux accepts duplicate rules, and a duplicate would
    /// survive single-match deletion), deletes are idempotent (an
    /// absent rule or route deletes cleanly). Rollback replays the
    /// inverse of CHANGED ops only — undoing a no-op delete would
    /// CREATE previously-absent state (the round-1 P1).
    fn exec(&mut self, op: NetOp) -> impl Future<Output = Result<bool, NetOpError>> + Send;

    /// The host's live rule/route tables as a survey: every table id
    /// referenced by any (v4) rule or route — owner unknowable from
    /// netlink alone, so the planner's lookalike bar treats them all
    /// as occupied.
    fn survey(
        &mut self,
        rt_tables_text: &str,
    ) -> impl Future<Output = Result<TableSurvey, NetOpError>> + Send;

    /// Which of `desired`'s operations have their state present on
    /// the host — a PROBE, no mutation, no plan validation (drift
    /// detection may probe anything; FR-40's repair diff is
    /// [`crate::route_drift::repair_ops`]).
    fn present_ops(
        &mut self,
        desired: &[NetOp],
    ) -> impl Future<Output = Result<Vec<NetOp>, NetOpError>> + Send;

    /// Disconnect's cleanup set (FR-39): the INVERSE of the
    /// session's still-present ADD-shaped operations — exactly the
    /// objects THIS session INSTALLED. `session` is what
    /// [`RouteTransaction::apply`] RETURNED (the mutations), never
    /// the built desired list: pre-existing state a session merely
    /// found already present was not installed and must not be
    /// removed. Del-shaped entries are ignored (their inverse would
    /// CREATE state — rust-review #1's FR-39 violation); the natural
    /// caller never passes them anyway. A TablePlan proves the table
    /// ALLOCATION, not every object a foreign manager later placed
    /// in the table; session scoping cannot touch those.
    fn cleanup_ops(
        &mut self,
        session: &[NetOp],
    ) -> impl Future<Output = Result<Vec<NetOp>, NetOpError>> + Send;
}

/// A transaction refused before it started — the op's table is a
/// lookalike (outside the plan; FR-34/IT-25).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("table {table} is outside the plan (owned: {owned:?}) — a lookalike; refusing the op")]
pub struct LookalikeTable {
    pub table: u32,
    pub owned: BTreeSet<u32>,
}

/// A failed apply: which op failed, why, how many ops before it were
/// rolled back (reverse order), and any rollback errors — a rollback
/// error means state may remain and MUST be surfaced, not swallowed.
/// Rollback errors are PAIRED with the op whose inverse failed
/// (replay order) — an unpaired list cannot be attributed once more
/// than one accumulates (rust-review #6).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("op {failed:?} failed ({error}); rolled back {rolled_back} op(s) in reverse order")]
pub struct ApplyFailure {
    pub failed: NetOp,
    pub error: NetOpError,
    pub rolled_back: usize,
    /// Rollback failures as (op-which-failed-to-undo, why), in
    /// replay order — empty on a clean rollback.
    pub rollback_errors: Vec<(NetOp, NetOpError)>,
}

/// A built transaction: validated ops plus the plan they were
/// validated against.
#[derive(Debug, Clone)]
pub struct RouteTransaction {
    plan: TablePlan,
    ops: Vec<NetOp>,
}

impl RouteTransaction {
    /// Start a transaction against a plan.
    pub fn new(plan: TablePlan) -> Self {
        RouteTransaction {
            plan,
            ops: Vec::new(),
        }
    }

    /// Add one op, refusing lookalike tables at CONSTRUCTION — a
    /// transaction containing an op on a table the plan does not own
    /// can never exist. TWO exemptions: the mark-BYPASS rule into the
    /// KERNEL MAIN table (a RULE with a fwmark, FR-61's outer-socket
    /// route-out), and the TABLELESS Blackhole rule (table 0 — a
    /// block has no destination table; the priority alone identifies
    /// it, FR-37's routing-layer v6 enforcement).
    pub fn op(mut self, op: NetOp) -> Result<Self, LookalikeTable> {
        let bypass_into_main = matches!(op, NetOp::AddRule(spec) | NetOp::DelRule(spec)
            if spec.table == KERNEL_MAIN && spec.fwmark.is_some());
        let blackhole = matches!(op, NetOp::AddRule(spec) | NetOp::DelRule(spec)
            if spec.action == RuleKind::Blackhole && spec.table == 0);
        if !bypass_into_main && !blackhole && !self.plan.owns(op.table()) {
            return Err(LookalikeTable {
                table: op.table(),
                owned: self.plan.ids(),
            });
        }
        self.ops.push(op);
        Ok(self)
    }

    /// Apply in order; on the first failure roll the CHANGED prefix
    /// back in REVERSE order and report. No-op operations (an absent
    /// delete, a present re-add) never enter the rollback set —
    /// undoing them would CREATE state that was never there (the
    /// round-1 P1).
    pub async fn apply<E: NetlinkExecutor>(
        self,
        executor: &mut E,
    ) -> Result<Vec<NetOp>, ApplyFailure> {
        let mut applied = Vec::new();
        for op in &self.ops {
            match executor.exec(*op).await {
                Ok(true) => applied.push(*op),
                Ok(false) => {} // idempotent no-op — nothing to undo
                Err(error) => {
                    let mut rollback_errors = Vec::new();
                    for done in applied.iter().rev() {
                        let undo = inverse(*done);
                        if let Err(rollback_error) = executor.exec(undo).await {
                            rollback_errors.push((undo, rollback_error));
                        }
                    }
                    return Err(ApplyFailure {
                        failed: *op,
                        error,
                        rolled_back: applied.len(),
                        rollback_errors,
                    });
                }
            }
        }
        Ok(applied)
    }
}

/// Survey + plan in one step: the connect path's entry point.
/// `persisted` is the daemon's OWN allocation record — the survey
/// alone cannot know it, and WITHOUT it a crash-restart's stale
/// rules (which make the former table read occupied) would push the
/// planner to a NEW id, leaving the stale state outside the plan's
/// ownership gate and uncleanable (the round-1 P1).
pub async fn plan_with<E: NetlinkExecutor>(
    executor: &mut E,
    rt_tables_text: &str,
    persisted: Option<crate::tables::PersistedTables>,
) -> Result<TablePlan, NetOpError> {
    let mut survey = executor.survey(rt_tables_text).await?;
    survey.persisted = persisted;
    Ok(plan_tables(&survey))
}

// ---------------------------------------------------------------------------
// The live executor: rtnetlink 0.23 over netlink-packet-route 0.33
// messages. v4-scoped for this slice (v6 leak prevention is FR-37's
// lane with its own proof surface).
// ---------------------------------------------------------------------------

use rtnetlink::packet_route::route::{
    RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use rtnetlink::packet_route::rule::RuleAction as NetlinkRuleAction;
use rtnetlink::packet_route::rule::{RuleAttribute, RuleMessage};
use rtnetlink::packet_route::{AddressFamily, route::RouteAddress};

/// The kernel's "real table id is in the attributes" marker for ids
/// that do not fit the u8 header field.
const RT_TABLE_COMPAT: u8 = 252;

/// The kernel's `main` table — the only non-plan table a transaction
/// may touch, and only through the mark-bypass RULE (the outer
/// sockets' route-out; FR-61).
pub const KERNEL_MAIN: u32 = 254;

/// rtnetlink-backed executor: add/del rule + route, survey by dump.
pub struct RtnetlinkExecutor {
    handle: rtnetlink::Handle,
}

impl RtnetlinkExecutor {
    /// Wrap a connected handle (the caller spawned the connection on
    /// its runtime).
    pub fn new(handle: rtnetlink::Handle) -> Self {
        RtnetlinkExecutor { handle }
    }

    fn build_route(spec: RouteSpec) -> RouteMessage {
        let mut message = RouteMessage::default();
        // The family follows the DESTINATION (a v6 default sent with
        // an Inet header is a duplicate of the v4 default — EEXIST;
        // caught by the isolated v6 IT after the branch rebuild).
        message.header.address_family = match spec.dest.addr {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };
        message.header.destination_prefix_length = spec.dest.len;
        message.header.table = if spec.table <= 255 {
            spec.table as u8
        } else {
            RT_TABLE_COMPAT
        };
        message.header.protocol = RouteProtocol::Static;
        // A gateway-less device route must be scope LINK — universe
        // is invalid without a gateway: ip rejects it client-side,
        // while raw netlink ACCEPTS the route and every send over it
        // then fails EINVAL (caught live by the kill-switch IT's
        // enforcement probe).
        message.header.scope = RouteScope::Link;
        message.header.kind = RouteType::Unicast;
        // The kernel's canonical form OMITS RTA_DST on a default
        // route — writing an explicit UNSPECIFIED destination is
        // non-canonical (the read-side matcher learned the same
        // lesson; the write side now matches).
        message.attributes = if spec.dest.len == 0 {
            vec![RouteAttribute::Oif(spec.oif)]
        } else {
            vec![
                RouteAttribute::Destination(spec.dest.addr.into()),
                RouteAttribute::Oif(spec.oif),
            ]
        };
        if spec.table > 255 {
            message.attributes.push(RouteAttribute::Table(spec.table));
        }
        message
    }

    /// The table a live rule message references (attribute first —
    /// the header field is a u8 that cannot carry 51820).
    fn rule_table(message: &RuleMessage) -> u32 {
        message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RuleAttribute::Table(table) => Some(*table),
                _ => None,
            })
            .unwrap_or(u32::from(message.header.table))
    }

    /// Whether a live rule message is OURS by FULL SHAPE (table,
    // priority, fwmark, ACTION, and the fwmask) — partial matches
    // are foreign state, never "present": a foreign rule with our
    // tuple but extra selectors or the pre-fix UNSPEC action must
    // not satisfy our spec (rust-review #8 + sec-audit F4).
    fn rule_matches(message: &RuleMessage, spec: RuleSpec) -> bool {
        let priority = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RuleAttribute::Priority(priority) => Some(*priority),
                _ => None,
            });
        let fwmark = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RuleAttribute::FwMark(mark) => Some(*mark),
                _ => None,
            });
        // The ACTION must match the SPEC (the round-4 P1): ToTable
        // specs match only ToTable rules; Blackhole specs match only
        // Blackhole rules. A pre-fix Unspec rule ("lookup none") is
        // nobody's match.
        let expected_action = match spec.action {
            RuleKind::ToTable => NetlinkRuleAction::ToTable,
            RuleKind::Blackhole => NetlinkRuleAction::Blackhole,
        };
        if message.header.action != expected_action {
            return false;
        }
        // FWMASK: our adds never set one — the kernel default
        // (0xffffffff) is ours; a narrower foreign mask with our
        // tuple is not.
        let fwmask = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RuleAttribute::FwMask(mask) => Some(*mask),
                _ => None,
            })
            .unwrap_or(0xffff_ffff);
        Self::rule_table(message) == spec.table
            && priority == Some(spec.priority)
            && fwmark == spec.fwmark
            && fwmask == 0xffff_ffff
    }

    /// The table a live route message references.
    fn route_table(message: &RouteMessage) -> u32 {
        message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::Table(table) => Some(*table),
                _ => None,
            })
            .or_else(|| {
                (message.header.table != RT_TABLE_COMPAT).then(|| u32::from(message.header.table))
            })
            .unwrap_or_default()
    }

    /// Whether a live route message is OURS by spec (table, family,
    // dest, oif) — the FAMILY is load-bearing: a destination-less /0
    // with the same table and oif exists in BOTH families, so without
    // the header check a surviving v4 default makes a drifted v6
    // default look present (repair never restores it) and a delete
    // can select the other family's route.
    fn route_matches(message: &RouteMessage, spec: RouteSpec) -> bool {
        let expected_family = match spec.dest.addr {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };
        if message.header.address_family != expected_family {
            return false;
        }
        let expected_dest = RouteAddress::from(spec.dest.addr);
        let dest = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::Destination(addr) => Some(addr),
                _ => None,
            });
        // The kernel OMITS RTA_DST for a default route — absence
        // means the unspecified destination (caught live by the
        // netns IT: the cleanup's route delete silently no-opped
        // against a /0 whose dump carried no Destination attribute).
        let dest_matches = match dest {
            Some(found) => *found == expected_dest,
            None => spec.dest.len == 0,
        };
        let oif = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::Oif(index) => Some(*index),
                _ => None,
            });
        // SCOPE and GATEWAY close the foreign-lookalike pair (the
        // round-2 P1s): our renders are ALWAYS scope Link (the
        // gateway-less EINVAL lesson) and NEVER carry a gateway — a
        // surviving parent-era UNIVERSE-scope route or a routed
        // (gateway) route with our tuple is foreign state, not ours.
        let gateway = message
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, RouteAttribute::Gateway(_)));
        Self::route_table(message) == spec.table
            && message.header.destination_prefix_length == spec.dest.len
            && dest_matches
            && oif == Some(spec.oif)
            && (message.header.address_family == AddressFamily::Inet6
                || message.header.scope == RouteScope::Link)
            && !gateway
    }

    async fn find_rule(&mut self, spec: RuleSpec) -> Result<Option<RuleMessage>, NetOpError> {
        let mut stream = self.handle.rule().get(spec.family.ip_version()).execute();
        while let Some(message) = stream.next().await {
            let message = message.map_err(|error| format!("rule dump: {error}"))?;
            if Self::rule_matches(&message, spec) {
                return Ok(Some(message));
            }
        }
        Ok(None)
    }

    async fn find_route(&mut self, spec: RouteSpec) -> Result<Option<RouteMessage>, NetOpError> {
        // Dump only the spec's family — the matcher carries the same
        // check as a belt, but the narrow dump keeps same-table-same-
        // oif cross-family candidates out of the search entirely.
        let mut template = RouteMessage::default();
        template.header.address_family = match spec.dest.addr {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };
        let mut stream = self.handle.route().get(template).execute();
        while let Some(message) = stream.next().await {
            let message = message.map_err(|error| format!("route dump: {error}"))?;
            if Self::route_matches(&message, spec) {
                return Ok(Some(message));
            }
        }
        Ok(None)
    }
}

impl NetlinkExecutor for RtnetlinkExecutor {
    async fn exec(&mut self, op: NetOp) -> Result<bool, NetOpError> {
        match op {
            NetOp::AddRule(spec) => {
                // Idempotent (the round-1 P1): Linux ACCEPTS duplicate
                // rules — a blind re-add after a retry/reconnect would
                // leave a duplicate that survives single-match
                // deletion. Present means done, not mutated.
                if self.find_rule(spec).await?.is_some() {
                    return Ok(false);
                }
                let request = self.handle.rule().add();
                // The ACTION follows the SPEC (the round-4 P1): the
                // enum existed but was dead code — every rule went
                // out as ToTable regardless. ToTable is the tunnel/
                // bypass shape; Blackhole is routing-level blocking
                // (FR-37 when the kill switch is unarmed).
                let mut request = match spec.action {
                    RuleKind::ToTable => request
                        .action(NetlinkRuleAction::ToTable)
                        .table_id(spec.table)
                        .priority(spec.priority),
                    RuleKind::Blackhole => request
                        .action(NetlinkRuleAction::Blackhole)
                        .priority(spec.priority),
                };
                if let Some(mark) = spec.fwmark {
                    request = request.fw_mark(mark);
                }
                // v4()/v6() return differently-parameterized request
                // types — execute within each arm.
                let result = match spec.family {
                    Family::V4 => request.v4().execute().await,
                    Family::V6 => request.v6().execute().await,
                };
                result.map_err(|error| format!("add rule: {error}"))?;
                Ok(true)
            }
            NetOp::DelRule(spec) => {
                // Idempotent: absent means already gone — NOT
                // mutated. LOOP the delete (rust-review #7):
                // Linux accepts duplicate rules, and twins installed
                // by a pre-fix version (or by hand) would otherwise
                // survive single-match deletion — the removal side of
                // the duplicate hazard the find-first add fixed.
                let mut mutated = false;
                // A sane bound (three lifetimes of duplicates) so a
                // pathological kernel can't loop us forever.
                for _ in 0..3 {
                    let Some(message) = self.find_rule(spec).await? else {
                        break;
                    };
                    self.handle
                        .rule()
                        .del(message)
                        .execute()
                        .await
                        .map_err(|error| format!("del rule: {error}"))?;
                    mutated = true;
                }
                Ok(mutated)
            }
            NetOp::AddRoute(spec) => {
                if self.find_route(spec).await?.is_some() {
                    return Ok(false);
                }
                self.handle
                    .route()
                    .add(Self::build_route(spec))
                    .execute()
                    .await
                    .map_err(|error| format!("add route: {error}"))?;
                Ok(true)
            }
            NetOp::DelRoute(spec) => {
                let Some(message) = self.find_route(spec).await? else {
                    return Ok(false);
                };
                self.handle
                    .route()
                    .del(message)
                    .execute()
                    .await
                    .map_err(|error| format!("del route: {error}"))?;
                Ok(true)
            }
        }
    }

    async fn survey(&mut self, rt_tables_text: &str) -> Result<TableSurvey, NetOpError> {
        let mut occupied = BTreeSet::new();
        let mut occupied_by_us = BTreeSet::new();
        // BOTH rule families (rules dump per-family — there is no
        // unspec rule dump): a table referenced only by another
        // manager's IPv6 rule read as FREE from a v4-only dump — the
        // planner would claim it and a session owning that table
        // would then delete the foreign rule (FR-39's violation).
        for family in [rtnetlink::IpVersion::V4, rtnetlink::IpVersion::V6] {
            let mut rules = self.handle.rule().get(family).execute();
            while let Some(message) = rules.next().await {
                let message = message.map_err(|error| format!("rule dump: {error}"))?;
                let table = Self::rule_table(&message);
                occupied.insert(table);
                // ENTRY-LEVEL OWNERSHIP PROOF (the planner's round-2
                // P1 contract): a table is occupied-by-US when a
                // dumped rule carries our canonical priority BAND —
                // 31699..=31700, route_drift's BYPASS/FULL_TUNNEL
                // constants (a private band no other manager picks by
                // accident). Our crash residue is rules-dominated:
                // routes die with their interface, our rules linger —
                // so rules carry the proof.
                let priority = message
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        RuleAttribute::Priority(priority) => Some(*priority),
                        _ => None,
                    });
                if priority.is_some_and(|priority| (31699..=31700).contains(&priority)) {
                    occupied_by_us.insert(table);
                }
            }
        }
        let mut routes = self.handle.route().get(RouteMessage::default()).execute();
        while let Some(message) = routes.next().await {
            let message = message.map_err(|error| format!("route dump: {error}"))?;
            occupied.insert(Self::route_table(&message));
        }
        // The kernel's own reserved ids (0/253/254/255 in the dump)
        // are planner-irrelevant but harmless to report.
        Ok(TableSurvey {
            named: crate::tables::parse_rt_tables(rt_tables_text),
            occupied,
            occupied_by_us,
            persisted: None,
        })
    }

    async fn present_ops(&mut self, desired: &[NetOp]) -> Result<Vec<NetOp>, NetOpError> {
        let mut present = Vec::new();
        for op in desired {
            let there = match op {
                NetOp::AddRule(spec) | NetOp::DelRule(spec) => {
                    self.find_rule(*spec).await?.is_some()
                }
                NetOp::AddRoute(spec) | NetOp::DelRoute(spec) => {
                    self.find_route(*spec).await?.is_some()
                }
            };
            if there {
                present.push(*op);
            }
        }
        Ok(present)
    }

    async fn cleanup_ops(&mut self, session: &[NetOp]) -> Result<Vec<NetOp>, NetOpError> {
        // Session-scoped by construction: probe the session's own
        // ADD-shaped specs and invert what is present. Nothing a
        // foreign manager placed anywhere — plan table or not — is
        // ever probed. Del-shaped entries are filtered BEFORE the
        // probe: a present Del's inverse is an ADD, and inverting it
        // would CREATE state at disconnect (rust-review #1) — the
        // exact FR-39 violation the session scoping exists to ban.
        let adds: Vec<NetOp> = session
            .iter()
            .copied()
            .filter(|op| matches!(op, NetOp::AddRule(_) | NetOp::AddRoute(_)))
            .collect();
        let present = self.present_ops(&adds).await?;
        Ok(present.iter().map(|op| inverse(*op)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records every exec; the fail closure decides refusals.
    struct FakeExecutor {
        calls: std::cell::RefCell<Vec<NetOp>>,
        fail: fn(NetOp) -> Option<NetOpError>,
    }

    impl FakeExecutor {
        fn succeeding() -> Self {
            FakeExecutor {
                calls: std::cell::RefCell::new(Vec::new()),
                fail: |_| None,
            }
        }
    }

    impl NetlinkExecutor for FakeExecutor {
        async fn exec(&mut self, op: NetOp) -> Result<bool, NetOpError> {
            self.calls.borrow_mut().push(op);
            (self.fail)(op).map_or(Ok(true), Err)
        }

        async fn survey(&mut self, _rt_tables_text: &str) -> Result<TableSurvey, NetOpError> {
            Ok(TableSurvey::default())
        }
        async fn present_ops(&mut self, _desired: &[NetOp]) -> Result<Vec<NetOp>, NetOpError> {
            Ok(Vec::new())
        }
        async fn cleanup_ops(&mut self, _session: &[NetOp]) -> Result<Vec<NetOp>, NetOpError> {
            Ok(Vec::new())
        }
    }

    fn plan() -> TablePlan {
        plan_tables(&TableSurvey::default())
    }

    fn rule(table: u32) -> RuleSpec {
        RuleSpec {
            table,
            priority: 31700,
            fwmark: None,
            family: Family::V4,
            action: RuleKind::ToTable,
        }
    }

    fn route(table: u32) -> RouteSpec {
        RouteSpec {
            table,
            dest: DestPrefix::V4_DEFAULT,
            oif: 1,
        }
    }

    #[test]
    fn route_matching_never_crosses_families() {
        // A v4 default-route message (family Inet, no RTA_DST — the
        // kernel's canonical /0) must NOT match a v6-default spec
        // with the same table and oif: without the family check a
        // surviving v4 default masks a drifted v6 default in
        // present_ops, and a delete can select the other family's
        // route.
        let mut v4_message = RouteMessage::default();
        v4_message.header.address_family = AddressFamily::Inet;
        v4_message.header.scope = RouteScope::Link;
        v4_message.header.table = RT_TABLE_COMPAT;
        v4_message.attributes = vec![RouteAttribute::Table(51820), RouteAttribute::Oif(7)];
        assert!(RtnetlinkExecutor::route_matches(
            &v4_message,
            RouteSpec {
                table: 51820,
                dest: DestPrefix::V4_DEFAULT,
                oif: 7
            }
        ));
        assert!(
            !RtnetlinkExecutor::route_matches(
                &v4_message,
                RouteSpec {
                    table: 51820,
                    dest: DestPrefix::V6_DEFAULT,
                    oif: 7
                }
            ),
            "a surviving v4 default must not mask a drifted v6 default"
        );
    }

    #[test]
    fn inverse_swaps_adds_and_deletes() {
        assert_eq!(
            inverse(NetOp::AddRule(rule(51820))),
            NetOp::DelRule(rule(51820))
        );
        assert_eq!(
            inverse(NetOp::DelRule(rule(51820))),
            NetOp::AddRule(rule(51820))
        );
        assert_eq!(
            inverse(NetOp::AddRoute(route(51820))),
            NetOp::DelRoute(route(51820))
        );
        assert_eq!(
            inverse(NetOp::DelRoute(route(51820))),
            NetOp::AddRoute(route(51820))
        );
    }

    #[test]
    fn lookalike_tables_are_refused_at_construction() {
        let error = RouteTransaction::new(plan())
            .op(NetOp::AddRule(rule(51823)))
            .expect_err("51823 is not in the preferred-plan");
        assert_eq!(error.table, 51823);
        assert!(error.owned.contains(&51820));
    }

    #[tokio::test]
    async fn a_clean_apply_runs_every_op_in_order() {
        let txn = RouteTransaction::new(plan())
            .op(NetOp::AddRule(rule(51820)))
            .expect("plan table")
            .op(NetOp::AddRoute(route(51820)))
            .expect("plan table");
        let mut executor = FakeExecutor::succeeding();
        let applied = txn.apply(&mut executor).await.expect("all ops succeed");
        assert_eq!(applied.len(), 2);
        assert_eq!(executor.calls.borrow().len(), 2);
    }

    #[tokio::test]
    async fn a_failure_rolls_the_applied_prefix_back_in_reverse() {
        // add-rule (ok) -> add-route (ok) -> del-rule-foreign (FAILS):
        // rollback must replay del-route THEN del-rule — reverse
        // order of the applied prefix, nothing else.
        struct FailDelRule9 {
            calls: std::cell::RefCell<Vec<NetOp>>,
        }
        impl NetlinkExecutor for FailDelRule9 {
            async fn exec(&mut self, op: NetOp) -> Result<bool, NetOpError> {
                self.calls.borrow_mut().push(op);
                match op {
                    NetOp::DelRule(spec) if spec.priority == 9 => {
                        Err("del-rule: kernel refused".into())
                    }
                    _ => Ok(true),
                }
            }
            async fn survey(&mut self, _: &str) -> Result<TableSurvey, NetOpError> {
                Ok(TableSurvey::default())
            }
            async fn present_ops(&mut self, _desired: &[NetOp]) -> Result<Vec<NetOp>, NetOpError> {
                Ok(Vec::new())
            }
            async fn cleanup_ops(&mut self, _session: &[NetOp]) -> Result<Vec<NetOp>, NetOpError> {
                Ok(Vec::new())
            }
        }
        let failing_op = NetOp::DelRule(RuleSpec {
            table: 51821,
            priority: 9,
            fwmark: Some(7),
            family: Family::V4,
            action: RuleKind::ToTable,
        });
        let txn = RouteTransaction::new(plan())
            .op(NetOp::AddRule(rule(51820)))
            .expect("plan table")
            .op(NetOp::AddRoute(route(51820)))
            .expect("plan table")
            .op(failing_op)
            .expect("plan table");
        let mut executor = FailDelRule9 {
            calls: std::cell::RefCell::new(Vec::new()),
        };
        let failure = txn.apply(&mut executor).await.expect_err("third op fails");
        assert_eq!(failure.failed, failing_op);
        assert_eq!(failure.rolled_back, 2);
        assert!(failure.rollback_errors.is_empty());
        assert_eq!(
            executor.calls.borrow().as_slice(),
            &[
                NetOp::AddRule(rule(51820)),
                NetOp::AddRoute(route(51820)),
                failing_op,
                // rollback, REVERSED:
                NetOp::DelRoute(route(51820)),
                NetOp::DelRule(rule(51820)),
            ]
        );
    }

    #[tokio::test]
    async fn no_op_deletes_are_never_rolled_back() {
        // The round-1 P1: a DelRule that found nothing is Ok(false) —
        // a LATER failure must not re-CREATE the absent rule by
        // replaying its inverse.
        struct NoOpDeletes {
            calls: std::cell::RefCell<Vec<NetOp>>,
        }
        impl NetlinkExecutor for NoOpDeletes {
            async fn exec(&mut self, op: NetOp) -> Result<bool, NetOpError> {
                self.calls.borrow_mut().push(op);
                match op {
                    NetOp::DelRule(_) | NetOp::DelRoute(_) => Ok(false),
                    NetOp::AddRule(_) => Ok(true),
                    NetOp::AddRoute(_) => Err("add route: kernel refused".into()),
                }
            }
            async fn survey(&mut self, _: &str) -> Result<TableSurvey, NetOpError> {
                Ok(TableSurvey::default())
            }
            async fn present_ops(&mut self, _desired: &[NetOp]) -> Result<Vec<NetOp>, NetOpError> {
                Ok(Vec::new())
            }
            async fn cleanup_ops(&mut self, _session: &[NetOp]) -> Result<Vec<NetOp>, NetOpError> {
                Ok(Vec::new())
            }
        }
        let failing = NetOp::AddRoute(route(51820));
        let txn = RouteTransaction::new(plan())
            .op(NetOp::DelRule(rule(51821)))
            .expect("plan table")
            .op(failing)
            .expect("plan table");
        let mut executor = NoOpDeletes {
            calls: std::cell::RefCell::new(Vec::new()),
        };
        let failure = txn.apply(&mut executor).await.expect_err("route add fails");
        assert_eq!(
            failure.rolled_back, 0,
            "the no-op delete never entered the rollback set"
        );
        assert!(
            executor
                .calls
                .borrow()
                .iter()
                .all(|call| !matches!(call, NetOp::AddRule(_))),
            "no inverse was replayed — nothing was created"
        );
    }

    #[tokio::test]
    async fn cleanup_never_inverts_del_shaped_session_entries() {
        /// rust-review #1: a Del-shaped session entry that is
        /// (still) present must NEVER be inverted — its inverse is
        /// an ADD, and disconnect would CREATE state.
        struct DelShapedPresent {
            calls: std::cell::RefCell<Vec<NetOp>>,
        }
        impl NetlinkExecutor for DelShapedPresent {
            async fn exec(&mut self, op: NetOp) -> Result<bool, NetOpError> {
                self.calls.borrow_mut().push(op);
                Ok(true)
            }
            async fn survey(&mut self, _: &str) -> Result<TableSurvey, NetOpError> {
                Ok(TableSurvey::default())
            }
            async fn present_ops(&mut self, desired: &[NetOp]) -> Result<Vec<NetOp>, NetOpError> {
                // Everything probed is present — the adversarial
                // shape: whatever survives the filter gets inverted.
                Ok(desired.to_vec())
            }
            async fn cleanup_ops(&mut self, session: &[NetOp]) -> Result<Vec<NetOp>, NetOpError> {
                let adds: Vec<NetOp> = session
                    .iter()
                    .copied()
                    .filter(|op| matches!(op, NetOp::AddRule(_) | NetOp::AddRoute(_)))
                    .collect();
                let present = self.present_ops(&adds).await?;
                Ok(present.iter().map(|op| inverse(*op)).collect())
            }
        }
        let mut executor = DelShapedPresent {
            calls: std::cell::RefCell::new(Vec::new()),
        };
        let cleanup = executor
            .cleanup_ops(&[
                NetOp::DelRule(RuleSpec {
                    table: 51820,
                    priority: 31700,
                    fwmark: None,
                    family: Family::V4,
                    action: RuleKind::ToTable,
                }),
                NetOp::AddRule(rule(51820)),
            ])
            .await
            .expect("cleanup");
        assert_eq!(
            cleanup,
            vec![NetOp::DelRule(rule(51820))],
            "only the ADD-shaped entry inverts; the Del never becomes an Add"
        );
    }

    #[tokio::test]
    async fn rollback_errors_are_surfaced_not_swallowed() {
        struct FailDelsAndSecondAdd {
            calls: std::cell::RefCell<Vec<NetOp>>,
        }
        impl NetlinkExecutor for FailDelsAndSecondAdd {
            async fn exec(&mut self, op: NetOp) -> Result<bool, NetOpError> {
                self.calls.borrow_mut().push(op);
                match op {
                    NetOp::DelRule(_) | NetOp::DelRoute(_) => Err("rollback refused".into()),
                    NetOp::AddRule(spec) if spec.priority == 42 => {
                        Err("add-rule: kernel refused".into())
                    }
                    _ => Ok(true),
                }
            }
            async fn survey(&mut self, _: &str) -> Result<TableSurvey, NetOpError> {
                Ok(TableSurvey::default())
            }
            async fn present_ops(&mut self, _desired: &[NetOp]) -> Result<Vec<NetOp>, NetOpError> {
                Ok(Vec::new())
            }
            async fn cleanup_ops(&mut self, _session: &[NetOp]) -> Result<Vec<NetOp>, NetOpError> {
                Ok(Vec::new())
            }
        }
        let txn = RouteTransaction::new(plan())
            .op(NetOp::AddRule(rule(51820)))
            .expect("plan table")
            .op(NetOp::AddRule(RuleSpec {
                table: 51820,
                priority: 42,
                fwmark: None,
                family: Family::V4,
                action: RuleKind::ToTable,
            }))
            .expect("plan table");
        let mut executor = FailDelsAndSecondAdd {
            calls: std::cell::RefCell::new(Vec::new()),
        };
        let failure = txn.apply(&mut executor).await.expect_err("second op fails");
        assert_eq!(failure.rolled_back, 1);
        assert_eq!(
            failure.rollback_errors,
            vec![(NetOp::DelRule(rule(51820)), "rollback refused".to_owned())],
            "the failed undo is PAIRED with its op"
        );
    }
}
