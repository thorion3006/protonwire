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
//! no-op reconnects). The executor's `owned_ops` (on
//! [`crate::route_txn::NetlinkExecutor`]) enumerates disconnect's
//! cleanup set: live state referencing PLAN tables only — FR-39's
//! "leave concurrently changed unowned state intact" is the
//! enumeration's table filter itself.

use crate::route_txn::{DestPrefix, NetOp, RouteSpec, RuleSpec};
use crate::tables::{TableKind, TablePlan};

/// The policy-rule priority band ProtonWire installs its rules at
/// (below the kernel's reserved 0–32766 user range ceiling; one band
/// for every ProtonWire rule, stable across reconnects).
pub const FULL_TUNNEL_RULE_PRIORITY: u32 = 31700;

/// The desired routing state for one connected full-tunnel session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredRoutes {
    /// The plan the session's tables were resolved against.
    pub plan: TablePlan,
    /// The TUN interface's kernel index (routes' output interface).
    pub tun_oif: u32,
}

/// Render the full-tunnel desired operations: the policy rule into
/// `protonwire-main` plus the v4 default route through the TUN
/// (FR-35). Deterministic order — the rule first, so a route never
/// exists unruled.
pub fn desired_ops(state: &DesiredRoutes) -> Vec<NetOp> {
    let main = state.plan.assignment(TableKind::Main).id;
    vec![
        NetOp::AddRule(RuleSpec {
            table: main,
            priority: FULL_TUNNEL_RULE_PRIORITY,
            fwmark: None,
        }),
        NetOp::AddRoute(RouteSpec {
            table: main,
            dest: DestPrefix::V4_DEFAULT,
            oif: state.tun_oif,
        }),
    ]
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
