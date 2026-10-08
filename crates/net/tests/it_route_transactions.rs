//! IT: the transactional netlink writer against a REAL kernel
//! (netns-gated, NFR-31; the `cargo xtask netns-it` runner executes
//! it inside a managed namespace — outside the runner it skips with
//! a disclosure and touches nothing).
//!
//! The full-tunnel shape end to end: plan the tables on the live
//! namespace, apply the rule+route transaction, verify by re-survey,
//! prove ROLLBACK on a doomed op, and clean up by inverse ops.

use futures_util::StreamExt;
use protonwire_net::netns;
use protonwire_net::route_drift::{DesiredRoutes, Ipv6Desired, desired_ops, repair_ops};
use protonwire_net::route_txn::{
    DestPrefix, Family, NetOp, NetlinkExecutor, RouteSpec, RouteTransaction, RtnetlinkExecutor,
    RuleKind, RuleSpec, plan_with,
};
use protonwire_net::tables::TableKind;

/// The `lo` interface index inside the namespace (the gate shim
/// brought it up; it stands in for the TUN-to-be as the routes'
/// output interface).
async fn lo_index(handle: &rtnetlink::Handle) -> u32 {
    let mut links = handle.link().get().match_name("lo").execute();
    while let Some(message) = links.next().await {
        let message = message.expect("link dump");
        if message.header.index != 0 {
            return message.header.index;
        }
    }
    panic!("no lo link inside the namespace");
}

#[tokio::test]
async fn it_route_transactions() {
    if !netns::gate("it_route_transactions") {
        return;
    }
    let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
    tokio::spawn(connection);
    let mut executor = RtnetlinkExecutor::new(handle.clone());

    // 1. PLAN against the live namespace: no policy rules, only the
    //    kernel's own tables — the preferred ids must be chosen.
    let plan = plan_with(&mut executor, "", None).await.expect("survey");
    assert_eq!(plan.assignment(TableKind::Main).id, 51820);
    assert_eq!(plan.assignment(TableKind::Bypass).id, 51821);
    assert_eq!(plan.assignment(TableKind::Lan).id, 51822);

    // 2. APPLY the full-tunnel shape: a rule into protonwire-main
    //    plus the default route (lo stands in for the TUN).
    let lo = lo_index(&handle).await;
    let rule = RuleSpec {
        table: 51820,
        priority: 31700,
        fwmark: None,
        family: Family::V4,
        action: RuleKind::ToTable,
    };
    let route = RouteSpec {
        table: 51820,
        dest: DestPrefix::V4_DEFAULT,
        oif: lo,
    };
    RouteTransaction::new(plan.clone())
        .op(NetOp::AddRule(rule))
        .expect("plan table")
        .op(NetOp::AddRoute(route))
        .expect("plan table")
        .apply(&mut executor)
        .await
        .expect("apply");
    let survey = executor.survey("").await.expect("re-survey");
    assert!(
        survey.occupied.contains(&51820),
        "the applied rule/route must reference the planned table"
    );

    // 3. ROLLBACK: a good bypass rule followed by a doomed route
    //    (output interface 99999 does not exist — the kernel refuses)
    //    must leave NOTHING behind: the rule is rolled back.
    let doomed = RouteSpec {
        table: 51821,
        dest: DestPrefix {
            addr: "10.99.0.0".parse().unwrap(),
            len: 24,
        },
        oif: 99999,
    };
    let failure = RouteTransaction::new(plan.clone())
        .op(NetOp::AddRule(RuleSpec {
            table: 51821,
            priority: 31701,
            fwmark: None,
            family: Family::V4,
            action: RuleKind::ToTable,
        }))
        .expect("plan table")
        .op(NetOp::AddRoute(doomed))
        .expect("plan table")
        .apply(&mut executor)
        .await
        .expect_err("the doomed route must fail");
    assert_eq!(
        failure.rolled_back, 1,
        "the bypass rule was applied then rolled back"
    );
    assert!(failure.rollback_errors.is_empty());
    let survey = executor.survey("").await.expect("re-survey after rollback");
    assert!(
        !survey.occupied.contains(&51821),
        "the rolled-back rule leaves no reference to the bypass table"
    );

    // 4. CLEANUP by inverse ops (idempotent deletes): the namespace
    //    ends as it began.
    RouteTransaction::new(plan)
        .op(NetOp::DelRule(rule))
        .expect("plan table")
        .op(NetOp::DelRoute(route))
        .expect("plan table")
        .apply(&mut executor)
        .await
        .expect("cleanup");
    let survey = executor.survey("").await.expect("final survey");
    assert!(
        !survey.occupied.contains(&51820),
        "cleanup leaves no reference to the main table"
    );
}

/// The desired-state lifecycle against the real kernel (FR-35/39/40,
/// M5 slice 3): apply the full-tunnel desired ops, prove an undrifted
/// host yields an EMPTY repair, drift a route away behind the
/// daemon's back and repair exactly it, then enumerate disconnect's
/// cleanup set — and prove a FOREIGN rule (another manager's, on a
/// non-plan table, installed raw because our writer would refuse it)
/// SURVIVES our cleanup (FR-39).
#[tokio::test]
async fn it_route_drift_and_cleanup() {
    if !netns::gate("it_route_drift_and_cleanup") {
        return;
    }
    let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
    tokio::spawn(connection);
    let mut executor = RtnetlinkExecutor::new(handle.clone());

    let plan = plan_with(&mut executor, "", None).await.expect("survey");
    let lo = lo_index(&handle).await;
    let desired = desired_ops(&DesiredRoutes {
        plan: plan.clone(),
        tun_oif: lo,
        bypass_mark: 0,
        ipv6: Ipv6Desired::Blocked,
        kill_switch_armed: true,
    });
    let NetOp::AddRoute(owned_route) = desired[1] else {
        panic!("desired[1] is the default route");
    };

    // Apply: the undrifted probe sees everything; the repair is EMPTY.
    RouteTransaction::new(plan.clone())
        .op(desired[0])
        .expect("plan table")
        .op(desired[1])
        .expect("plan table")
        .apply(&mut executor)
        .await
        .expect("apply");
    let present = executor.present_ops(&desired).await.expect("probe");
    assert_eq!(present.len(), desired.len());
    assert!(repair_ops(&desired, &present).is_empty(), "undrifted host");

    // DRIFT: the route disappears; the probe misses exactly it; the
    // repair restores exactly it.
    RouteTransaction::new(plan.clone())
        .op(NetOp::DelRoute(owned_route))
        .expect("plan table")
        .apply(&mut executor)
        .await
        .expect("drift the route away");
    let present = executor.present_ops(&desired).await.expect("probe");
    assert_eq!(present, vec![desired[0]]);
    let repair = repair_ops(&desired, &present);
    assert_eq!(repair, vec![desired[1]]);
    RouteTransaction::new(plan.clone())
        .op(repair[0])
        .expect("plan table")
        .apply(&mut executor)
        .await
        .expect("repair");
    let present = executor.present_ops(&desired).await.expect("probe");
    assert_eq!(present.len(), desired.len());

    // FOREIGN state: another manager's rule on a non-plan table,
    // installed RAW (our writer refuses non-plan ops by construction).
    handle
        .rule()
        .add()
        .action(rtnetlink::packet_route::rule::RuleAction::ToTable)
        .table_id(4000)
        .priority(32000)
        .v4()
        .execute()
        .await
        .expect("foreign rule");

    // CLEANUP enumerates only plan-table state — our rule + our route.
    let cleanup = executor
        .cleanup_ops(&desired)
        .await
        .expect("owned enumeration");
    assert_eq!(cleanup.len(), 2, "exactly our rule and our route");
    assert!(cleanup.iter().any(|op| matches!(op, NetOp::DelRule(_))));
    assert!(cleanup.iter().any(|op| matches!(op, NetOp::DelRoute(_))));
    let mut txn = RouteTransaction::new(plan.clone());
    for op in cleanup {
        txn = txn.op(op).expect("plan table");
    }
    txn.apply(&mut executor).await.expect("cleanup");

    // FR-39: no plan-table reference remains; the foreign rule
    // SURVIVED our cleanup untouched.
    let survey = executor.survey("").await.expect("final survey");
    for id in plan.ids() {
        assert!(
            !survey.occupied.contains(&id),
            "plan table {id} unreferenced after cleanup"
        );
    }
    let foreign = RuleSpec {
        table: 4000,
        priority: 32000,
        fwmark: None,
        family: Family::V4,
        action: RuleKind::ToTable,
    };
    let survived = executor
        .present_ops(&[NetOp::AddRule(foreign)])
        .await
        .expect("probe");
    assert_eq!(
        survived,
        vec![NetOp::AddRule(foreign)],
        "unowned state stays"
    );
}

/// The tunnelled-v6 pass (FR-35's ::/0): the desired set carries
/// both families; everything applies, probes complete, and the
/// session-scoped cleanup removes exactly it.
#[tokio::test]
async fn it_tunnelled_v6_end_to_end() {
    if !netns::gate("it_tunnelled_v6_end_to_end") {
        return;
    }
    let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
    tokio::spawn(connection);
    let mut executor = RtnetlinkExecutor::new(handle.clone());
    let plan = plan_with(&mut executor, "", None).await.expect("survey");
    let lo = lo_index(&handle).await;
    let desired = desired_ops(&DesiredRoutes {
        plan: plan.clone(),
        tun_oif: lo,
        bypass_mark: 0,
        ipv6: Ipv6Desired::Tunnelled,
        kill_switch_armed: true,
    });
    assert_eq!(desired.len(), 4, "v4 pair + v6 pair");
    let mut txn = RouteTransaction::new(plan.clone());
    for op in &desired {
        txn = txn.op(*op).expect("plan table");
    }
    txn.apply(&mut executor).await.expect("v6 tunnelled apply");
    let present = executor.present_ops(&desired).await.expect("probe");
    assert_eq!(present.len(), 4, "both families present");
    assert!(repair_ops(&desired, &present).is_empty());
    let cleanup = executor.cleanup_ops(&desired).await.expect("cleanup set");
    assert_eq!(cleanup.len(), 4, "the session's four objects");
    let mut txn = RouteTransaction::new(plan.clone());
    for op in cleanup {
        txn = txn.op(op).expect("plan table");
    }
    txn.apply(&mut executor).await.expect("final cleanup");
    let survey = executor.survey("").await.expect("final survey");
    for id in plan.ids() {
        assert!(
            !survey.occupied.contains(&id),
            "plan table {id} unreferenced after the v6 cleanup"
        );
    }
}

/// A preferred table referenced ONLY by another manager's IPv6 rule
/// is OCCUPIED: the survey must see v6 rules before the planner
/// claims the table (else a session owning that table would delete
/// the foreign rule — FR-39's violation).
#[tokio::test]
async fn it_v6_occupation_is_surveyed() {
    if !netns::gate("it_v6_occupation_is_surveyed") {
        return;
    }
    let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
    tokio::spawn(connection);
    let mut executor = RtnetlinkExecutor::new(handle.clone());

    handle
        .rule()
        .add()
        .action(rtnetlink::packet_route::rule::RuleAction::ToTable)
        .table_id(51820)
        .priority(9000)
        .v6()
        .execute()
        .await
        .expect("foreign v6 rule");

    let survey = executor.survey("").await.expect("survey");
    assert!(
        survey.occupied.contains(&51820),
        "a v6-rule-referenced table is occupied"
    );

    let plan = plan_with(&mut executor, "", None).await.expect("re-plan");
    let main = plan.assignment(TableKind::Main).id;
    assert_ne!(main, 51820, "the v6-occupied preferred id is never claimed");
    assert!(!plan.owns(51820));

    // Tidy: remove the foreign rule by raw dump-and-delete.
    let mut rules = handle.rule().get(rtnetlink::IpVersion::V6).execute();
    while let Some(message) = rules.next().await {
        let message = message.expect("v6 rule dump");
        let table = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                rtnetlink::packet_route::rule::RuleAttribute::Table(table) => Some(*table),
                _ => None,
            });
        if table == Some(51820) {
            handle
                .rule()
                .del(message)
                .execute()
                .await
                .expect("foreign cleanup");
        }
    }
}

/// QA rec 1: the v4 flavor of the occupation survey — a foreign v4
/// rule pre-occupies the preferred table id, the planner allocates
/// elsewhere, and the foreign rule is NOT touched.
#[tokio::test]
async fn it_v4_occupation_is_surveyed() {
    if !netns::gate("it_v4_occupation_is_surveyed") {
        return;
    }
    let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
    tokio::spawn(connection);
    let mut executor = RtnetlinkExecutor::new(handle.clone());
    handle
        .rule()
        .add()
        .action(rtnetlink::packet_route::rule::RuleAction::ToTable)
        .table_id(51820)
        .priority(8000)
        .v4()
        .execute()
        .await
        .expect("foreign v4 rule");
    let survey = executor.survey("").await.expect("survey");
    assert!(survey.occupied.contains(&51820));
    assert!(
        !survey.occupied_by_us.contains(&51820),
        "priority 8000 is not our band"
    );
    let plan = plan_with(&mut executor, "", None).await.expect("plan");
    let main = plan.assignment(TableKind::Main).id;
    assert_ne!(main, 51820, "the v4-occupied preferred id is never claimed");
    assert!(!plan.owns(51820));
    // Tidy.
    let mut rules = handle.rule().get(rtnetlink::IpVersion::V4).execute();
    while let Some(message) = rules.next().await {
        let m = message.expect("dump");
        let table = m.attributes.iter().find_map(|a| match a {
            rtnetlink::packet_route::rule::RuleAttribute::Table(t) => Some(*t),
            _ => None,
        });
        if table == Some(51820) {
            handle.rule().del(m).execute().await.expect("cleanup");
        }
    }
}

/// QA rec 6: the crash-replan flow — after a crash the stale rules
/// are still in the kernel, the persisted record + entry-level proof
/// (priority band) reclaims the table, and the session-scoped
/// cleanup removes exactly the stale state.
#[tokio::test]
async fn it_crash_replan_owns_stale_state() {
    if !netns::gate("it_crash_replan_owns_stale_state") {
        return;
    }
    let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
    tokio::spawn(connection);
    let mut executor = RtnetlinkExecutor::new(handle.clone());

    // Session 1: plan, apply, then CRASH (no cleanup).
    let plan1 = plan_with(&mut executor, "", None).await.expect("plan 1");
    let lo = lo_index(&handle).await;
    let desired1 = desired_ops(&DesiredRoutes {
        plan: plan1.clone(),
        tun_oif: lo,
        bypass_mark: 0,
        ipv6: Ipv6Desired::Blocked,
        kill_switch_armed: true,
    });
    let mut txn = RouteTransaction::new(plan1.clone());
    for op in &desired1 {
        txn = txn.op(*op).expect("plan table");
    }
    txn.apply(&mut executor).await.expect("session 1 applies");
    // CRASH: no cleanup. The stale rules remain.

    // Session 2: re-plan with the persisted record. The survey sees
    // the stale rules (occupied) AND the entry-level proof (our
    // priority band) → the persisted id is RECLAIMED.
    let persisted = crate_persisted_from_plan(&plan1);
    let plan2 = plan_with(&mut executor, "", Some(persisted))
        .await
        .expect("plan 2");
    assert_eq!(
        plan2.assignment(TableKind::Main).provenance,
        protonwire_net::tables::Provenance::Persisted,
        "the crash's stale rules + the entry-level proof reclaim the id"
    );
    assert_eq!(
        plan2.assignment(TableKind::Main).id,
        plan1.assignment(TableKind::Main).id
    );

    // The cleanup removes the stale state.
    let cleanup = executor.cleanup_ops(&desired1).await.expect("cleanup");
    let mut txn = RouteTransaction::new(plan2.clone());
    for op in cleanup {
        txn = txn.op(op).expect("plan table");
    }
    txn.apply(&mut executor).await.expect("stale cleanup");
    let survey = executor.survey("").await.expect("post-cleanup survey");
    for id in plan2.ids() {
        assert!(
            !survey.occupied.contains(&id),
            "plan table {id} unreferenced after crash cleanup"
        );
    }
}

fn crate_persisted_from_plan(
    plan: &protonwire_net::tables::TablePlan,
) -> protonwire_net::tables::PersistedTables {
    protonwire_net::tables::PersistedTables {
        main: plan.assignment(TableKind::Main).id,
        bypass: plan.assignment(TableKind::Bypass).id,
        lan: plan.assignment(TableKind::Lan).id,
    }
}
