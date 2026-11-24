//! IT-31: the bypass-mark allocator against LIVE kernel state
//! (netns-gated, NFR-31). A foreign ip-rule fwmark and a foreign
//! nftables meta-mark match are seeded before the survey; the
//! allocator must avoid BOTH, and the session re-check must flag
//! both seeds as collisions. Our own priority band and our own table
//! are exercised from the other side: a rule in the band referencing
//! the daemon's current mark does NOT collide (attribution).

use protonwire_net::mark::{self, MARK_MAX, MARK_MIN};
use protonwire_net::netns;
use protonwire_net::route_txn::{NetOp, NetlinkExecutor, RtnetlinkExecutor};

/// A foreign rule's fwmark (outside our band, inside the allocatable
/// space — the adversarial neighbor).
const FOREIGN_RULE_MARK: u32 = 0x0011_0001;
/// A foreign nftables mark match (same conditions).
const FOREIGN_NFT_MARK: u32 = 0x0022_0002;

#[tokio::test]
async fn it31_the_allocator_avoids_live_foreign_marks() {
    if !netns::gate("it31: the bypass-mark allocator vs live foreign marks") {
        return;
    }
    let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
    tokio::spawn(connection);
    let mut executor = RtnetlinkExecutor::new(handle.clone());

    // === SEED 1: a foreign policy rule routing by FOREIGN_RULE_MARK
    // (priority 100 — nowhere near our 31699..=31700 band). ===
    executor
        .exec(NetOp::AddRule(protonwire_net::route_txn::RuleSpec {
            table: 1000,
            priority: 100,
            fwmark: Some(FOREIGN_RULE_MARK),
            family: protonwire_net::route_txn::Family::V4,
            action: protonwire_net::route_txn::RuleKind::ToTable,
        }))
        .await
        .expect("seed the foreign rule");

    // === SEED 2: a foreign nftables table whose rule matches
    // FOREIGN_NFT_MARK (the Meta(Mark)→Cmp(Eq) shape our own kill
    // switch renders — in a REGULAR chain: the survey reads
    // configuration, evaluation is not required). ===
    {
        use rustables::expr::{Cmp, CmpOp, Meta, MetaType};
        use rustables::{Batch, Chain, MsgType, ProtocolFamily, Rule, Table};
        let mut batch = Batch::new();
        let table = Table::new(ProtocolFamily::Inet).with_name("foreign-marks");
        batch.add(&table, MsgType::Add);
        let chain = Chain::new(&table).with_name("match-marks");
        batch.add(&chain, MsgType::Add);
        let rule = Rule::new(&chain)
            .expect("foreign mark rule")
            .with_expr(Meta::new(MetaType::Mark))
            .with_expr(Cmp::new(CmpOp::Eq, FOREIGN_NFT_MARK.to_le_bytes()));
        batch.add(&rule, MsgType::Add);
        batch.send().expect("seed the foreign nft table");
    }

    // === THE ALLOCATION: neither seed may come back. ===
    let chosen = mark::allocate(&mut executor)
        .await
        .expect("allocate against the seeded world");
    assert!(
        (MARK_MIN..=MARK_MAX).contains(&chosen),
        "the mark is inside the allocatable space: {chosen:#x}"
    );
    assert_ne!(chosen, FOREIGN_RULE_MARK, "the foreign rule mark is taken");
    assert_ne!(chosen, FOREIGN_NFT_MARK, "the foreign nft mark is taken");

    // === THE SESSION RE-CHECK: both seeds collide; a fresh mark
    // does not; and a rule in OUR band referencing a mark does NOT
    // collide (attribution — reconnect must not fight its own
    // crash residue). ===
    assert!(
        mark::session_collision(&mut executor, FOREIGN_RULE_MARK)
            .await
            .expect("netlink half"),
        "the foreign rule mark collides"
    );
    assert!(
        mark::session_collision(&mut executor, FOREIGN_NFT_MARK)
            .await
            .expect("both halves"),
        "the foreign nft mark collides"
    );
    assert!(
        !mark::session_collision(&mut executor, chosen)
            .await
            .expect("both halves"),
        "the freshly allocated mark is free"
    );

    // OUR band: a rule at priority 31699 routing by OUR_MARK is our
    // own (prior-session residue) — not a collision.
    const OUR_RESIDUE_MARK: u32 = 0x0033_0003;
    executor
        .exec(NetOp::AddRule(protonwire_net::route_txn::RuleSpec {
            table: 1001,
            priority: 31699, // BYPASS_RULE_PRIORITY — ours by definition
            fwmark: Some(OUR_RESIDUE_MARK),
            family: protonwire_net::route_txn::Family::V4,
            action: protonwire_net::route_txn::RuleKind::ToTable,
        }))
        .await
        .expect("seed our own residue rule");
    assert!(
        !mark::session_collision(&mut executor, OUR_RESIDUE_MARK)
            .await
            .expect("both halves"),
        "our own band's residue rule does not collide with itself"
    );

    // === CLEANUP (netns-isolated, but tidy): drop the foreign
    // table; the rules die with the namespace. ===
    {
        use rustables::{Batch, MsgType};
        for table in rustables::list_tables().expect("list tables") {
            if table.get_name().is_some_and(|name| name == "foreign-marks") {
                let mut batch = Batch::new();
                batch.add(&table, MsgType::Del);
                batch.send().expect("drop the foreign table");
            }
        }
    }
}
