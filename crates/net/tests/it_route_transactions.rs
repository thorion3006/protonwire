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
    let plan = plan_with(&mut executor, "").await.expect("survey");
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
