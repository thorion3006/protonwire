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
use protonwire_net::route_drift::{DesiredRoutes, desired_ops, repair_ops};
use protonwire_net::route_txn::{
    DestPrefix, NetOp, NetlinkExecutor, RouteSpec, RouteTransaction, RtnetlinkExecutor, RuleSpec,
    plan_with,
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

    let plan = plan_with(&mut executor, "").await.expect("survey");
    let lo = lo_index(&handle).await;
    let desired = desired_ops(&DesiredRoutes {
        plan: plan.clone(),
        tun_oif: lo,
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
        .table_id(4000)
        .priority(32000)
        .v4()
        .execute()
        .await
        .expect("foreign rule");

    // CLEANUP enumerates only plan-table state — our rule + our route.
    let cleanup = executor.owned_ops(&plan).await.expect("owned enumeration");
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
