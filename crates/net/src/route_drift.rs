//! The routing desired-state lifecycle (FR-35/39/40, M5 slice 3):
//! what a connected full-tunnel session MUST look like on the host,
//! how drift from it is detected and repaired, and how disconnect
//! removes exactly the state ProtonWire owns — never a lookalike's,
//! never another manager's.
//!
//! [`crate::route_drift::desired_ops`] renders the full-tunnel shape (FR-35, v4 this
//! slice — the v6 default route rides FR-37's leak-prevention lane
//! with its own proof surface). [`crate::route_drift::repair_ops`] is the FR-40 diff:
//! desired state that has gone missing while connected, restored
//! idempotently (a present-and-correct host yields an EMPTY repair —
//! no-op reconnects). The executor's `cleanup_ops` (on
//! [`crate::route_txn::NetlinkExecutor`]) inverts the SESSION's
//! still-present operations — exactly what this session installed,
//! never anything a foreign manager placed in a plan table
//! mid-session (FR-39's "leave concurrently changed unowned state
//! intact" is the session scoping itself).

use crate::route_txn::{DestPrefix, Family, KERNEL_MAIN, NetOp, RouteSpec, RuleSpec};
use crate::tables::{TableKind, TablePlan};

/// The policy-rule priority band ProtonWire installs its rules at
/// (below the kernel's reserved 0–32766 user range ceiling; one band
/// for every ProtonWire rule, stable across reconnects).
pub const FULL_TUNNEL_RULE_PRIORITY: u32 = 31700;

/// What the session wants from IPv6 (FR-35's ::/0 vs FR-37's leak
/// block).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Desired {
    /// The tunnel carries v6: a v6 rule + the ::/0 default route
    /// through the TUN (FR-35).
    Tunnelled,
    /// IPv6 over VPN is unavailable: NO v6 routing is installed and
    /// the kill switch's inet-family default drop blocks every v6
    /// egress (FR-37/FR-62 — a blocked family needs no rules of its
    /// own to die).
    Blocked,
}

/// The bypass rules sit ONE above the tunnel band: evaluated first,
/// they keep the daemon's own marked outer sockets on the normal
/// uplink — without them the unconditional full-tunnel rule swallows
/// ProTUN's transport and routes the tunnel back into itself (the
/// marks.rs contract; the round-1 P1). BOTH families: the outer
/// sockets may be v6 even when the tunnel carries no v6.
pub const BYPASS_RULE_PRIORITY: u32 = FULL_TUNNEL_RULE_PRIORITY - 1;

/// The desired routing state for one connected full-tunnel session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredRoutes {
    /// The plan the session's tables were resolved against.
    pub plan: TablePlan,
    /// The TUN interface's kernel index (routes' output interface).
    pub tun_oif: u32,
    /// The daemon's bypass mark (0 disables the bypass rules — tests
    /// and dry-runs; production always passes the real mark, FR-61:
    /// only the active daemon/ProTUN instance marks its sockets).
    pub bypass_mark: u32,
    /// The session's IPv6 posture.
    pub ipv6: Ipv6Desired,
}

/// Render the full-tunnel desired operations. Deterministic order:
/// the MARK BYPASS rules first (they must win lookup before the
/// catch-all; BOTH families — the daemon's outer sockets may be v6),
/// then per family the tunnel rule and its default route through the
/// TUN — FR-35, v4 always, v6 when tunnelled; rules before routes,
/// so a route never exists unruled. Blocked v6 renders NOTHING for
/// v6: the kill switch's inet-family default drop is the block
/// (FR-37), and the KILL SWITCH ARMS BEFORE these ops apply — the
/// connect sequence's contract (round-1 P1: routing first would
/// leave a v6 escape window until the switch lands).
pub fn desired_ops(state: &DesiredRoutes) -> Vec<NetOp> {
    let main = state.plan.assignment(TableKind::Main).id;
    let mut ops = Vec::new();
    if state.bypass_mark != 0 {
        ops.push(NetOp::AddRule(RuleSpec {
            table: KERNEL_MAIN,
            priority: BYPASS_RULE_PRIORITY,
            fwmark: Some(state.bypass_mark),
            family: Family::V4,
        }));
        ops.push(NetOp::AddRule(RuleSpec {
            table: KERNEL_MAIN,
            priority: BYPASS_RULE_PRIORITY,
            fwmark: Some(state.bypass_mark),
            family: Family::V6,
        }));
    }
    ops.push(NetOp::AddRule(RuleSpec {
        table: main,
        priority: FULL_TUNNEL_RULE_PRIORITY,
        fwmark: None,
        family: Family::V4,
    }));
    ops.push(NetOp::AddRoute(RouteSpec {
        table: main,
        dest: DestPrefix::V4_DEFAULT,
        oif: state.tun_oif,
    }));
    if state.ipv6 == Ipv6Desired::Tunnelled {
        ops.push(NetOp::AddRule(RuleSpec {
            table: main,
            priority: FULL_TUNNEL_RULE_PRIORITY,
            fwmark: None,
            family: Family::V6,
        }));
        ops.push(NetOp::AddRoute(RouteSpec {
            table: main,
            dest: DestPrefix::V6_DEFAULT,
            oif: state.tun_oif,
        }));
    }
    ops
}

/// The FR-40 repair diff: `desired` operations whose state is NOT in
/// `present`, in desired order. Idempotent — an undrifted host
/// yields an empty repair.
pub fn repair_ops(desired: &[NetOp], present: &[NetOp]) -> Vec<NetOp> {
    desired
        .iter()
        .filter(|op| !present.contains(op))
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::{TableSurvey, plan_tables};

    fn plan() -> TablePlan {
        plan_tables(&TableSurvey::default())
    }

    fn desired(oif: u32) -> DesiredRoutes {
        DesiredRoutes {
            plan: plan(),
            tun_oif: oif,
            bypass_mark: 0,
            ipv6: Ipv6Desired::Blocked,
        }
    }

    fn desired_bypass(oif: u32, mark: u32) -> DesiredRoutes {
        DesiredRoutes {
            plan: plan(),
            tun_oif: oif,
            bypass_mark: mark,
            ipv6: Ipv6Desired::Blocked,
        }
    }

    #[test]
    fn full_tunnel_desired_shape() {
        let ops = desired_ops(&desired(7));
        assert_eq!(
            ops,
            vec![
                NetOp::AddRule(RuleSpec {
                    table: 51820,
                    priority: FULL_TUNNEL_RULE_PRIORITY,
                    fwmark: None,
                    family: Family::V4,
                }),
                NetOp::AddRoute(RouteSpec {
                    table: 51820,
                    dest: DestPrefix::V4_DEFAULT,
                    oif: 7,
                }),
            ]
        );
    }

    #[test]
    fn a_bypass_mark_renders_the_outer_socket_route_out_first() {
        // The round-1 P1: without a higher-priority mark rule the
        // unconditional full-tunnel rule swallows ProTUN's own marked
        // outer sockets — the tunnel routed back into itself.
        let ops = desired_ops(&desired_bypass(7, 0x21));
        assert_eq!(
            ops,
            vec![
                NetOp::AddRule(RuleSpec {
                    table: KERNEL_MAIN,
                    priority: BYPASS_RULE_PRIORITY,
                    fwmark: Some(0x21),
                    family: Family::V4,
                }),
                NetOp::AddRule(RuleSpec {
                    table: KERNEL_MAIN,
                    priority: BYPASS_RULE_PRIORITY,
                    fwmark: Some(0x21),
                    family: Family::V6,
                }),
                NetOp::AddRule(RuleSpec {
                    table: 51820,
                    priority: FULL_TUNNEL_RULE_PRIORITY,
                    fwmark: None,
                    family: Family::V4,
                }),
                NetOp::AddRoute(RouteSpec {
                    table: 51820,
                    dest: DestPrefix::V4_DEFAULT,
                    oif: 7,
                }),
            ],
            "the bypass rule precedes the catch-all it must outrank"
        );
    }

    #[test]
    fn a_complete_host_needs_no_repair() {
        let desired = desired_ops(&desired(7));
        assert!(
            repair_ops(&desired, &desired).is_empty(),
            "undrifted: empty repair"
        );
        // A present SUPERSET (state we did not ask for) still yields
        // no repair — extraneous state is cleanup's/leak lane's call,
        // never silently deleted by the repair path.
        let mut superset = desired.clone();
        superset.push(NetOp::AddRule(RuleSpec {
            table: 51821,
            priority: 9,
            fwmark: None,
            family: Family::V4,
        }));
        assert!(repair_ops(&desired, &superset).is_empty());
    }

    #[test]
    fn missing_state_is_repaired_in_desired_order() {
        let desired = desired_ops(&desired(7));
        // The route drifted away (deleted behind the daemon's back);
        // the rule survives.
        let present = vec![desired[0]];
        assert_eq!(repair_ops(&desired, &present), vec![desired[1]]);
        // Everything missing: full restore, desired order.
        assert_eq!(repair_ops(&desired, &[]), desired);
        // The rule missing instead:
        let present = vec![desired[1]];
        assert_eq!(repair_ops(&desired, &present), vec![desired[0]]);
    }
}
