//! IT: the nftables kill switch against a REAL kernel (netns-gated,
//! NFR-31; the `cargo xtask netns-it` runner executes it inside a
//! managed namespace — outside the runner it skips with a disclosure
//! and touches nothing).
//!
//! The full FR-59..65 contract: fresh apply + validate, the counted
//! drop rule DROPPING a real leak probe (enforcement, not just
//! ruleset presence), the loopback permit, an atomic re-apply at a
//! new generation, and the LOOKALIKE refusal — a foreign `protonwire`
//! table without our marker is never flushed, apply fails closed.

use protonwire_net::kill_switch::{
    self, ApplyDecision, GenerationId, KillSwitchError, KillSwitchPolicy,
};
use protonwire_net::netns;
use rustables::{Batch, MsgType, ProtocolFamily, Table};

use std::net::UdpSocket;

const TUN_STANDIN: &str = "pw-tun0";
const UPLINK_STANDIN: &str = "pw-uplink0";

#[test]
fn it_kill_switch() {
    if !netns::gate("it_kill_switch") {
        return;
    }
    // ROUTES FIRST — the daemon's order (tunnel routes exist before
    // the kill switch arms). A DUMMY interface stands in for the TUN
    // (a default route over `lo` cannot carry off-link packets — the
    // kernel answers EINVAL — while a dummy egresses fine), and a
    // SECOND dummy stands in for the uplink: the enforcement probe
    // binds to it (SO_BINDTODEVICE) so its egress is deterministically
    // NON-tunnel — the shape of a real leak.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let tun_oif = runtime.block_on(async {
        let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
        tokio::spawn(connection);
        handle
            .link()
            .add(rtnetlink::LinkDummy::new(TUN_STANDIN).up().build())
            .execute()
            .await
            .expect("dummy TUN stand-in");
        handle
            .link()
            .add(rtnetlink::LinkDummy::new(UPLINK_STANDIN).up().build())
            .execute()
            .await
            .expect("dummy uplink stand-in");
        let mut links = handle.link().get().match_name(TUN_STANDIN).execute();
        use futures_util::StreamExt;
        let mut tun_oif = 0;
        while let Some(message) = links.next().await {
            let message = message.expect("link dump");
            if message.header.index != 0 {
                tun_oif = message.header.index;
            }
        }
        assert_ne!(tun_oif, 0, "the dummy stand-in exists");
        let mut uplinks = handle.link().get().match_name(UPLINK_STANDIN).execute();
        let mut uplink_oif = 0;
        while let Some(message) = uplinks.next().await {
            let message = message.expect("link dump");
            if message.header.index != 0 {
                uplink_oif = message.header.index;
            }
        }
        assert_ne!(uplink_oif, 0, "the uplink stand-in exists");
        // Source addresses: without one on the egress, UDP sends fail
        // EINVAL before the output hook.
        handle
            .address()
            .add(
                tun_oif,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 2, 0, 2)),
                32,
            )
            .execute()
            .await
            .expect("TUN stand-in address");
        handle
            .address()
            .add(
                uplink_oif,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 254)),
                24,
            )
            .execute()
            .await
            .expect("uplink stand-in address");
        let mut executor = protonwire_net::route_txn::RtnetlinkExecutor::new(handle.clone());
        let plan = protonwire_net::route_txn::plan_with(&mut executor, "")
            .await
            .expect("survey");
        let desired =
            protonwire_net::route_drift::desired_ops(&protonwire_net::route_drift::DesiredRoutes {
                plan: plan.clone(),
                tun_oif,
            });
        let mut txn = protonwire_net::route_txn::RouteTransaction::new(plan);
        for op in desired {
            txn = txn.op(op).expect("plan table");
        }
        txn.apply(&mut executor)
            .await
            .expect("full-tunnel routes installed");
        tun_oif
    });

    let policy = KillSwitchPolicy {
        tun_ifindex: tun_oif,
        allow_dhcp_v4: true,
        lan_ifindex: None,
        bypass_mark: 0x21,
    };

    // 1. FRESH APPLY + VALIDATE + BEHAVIORAL PROBE: the marker
    //    generation, the output chain, the exact rendered rule count,
    //    and a leak-shaped probe that DIES at the counted drop.
    kill_switch::apply(TUN_STANDIN, UPLINK_STANDIN, &policy, GenerationId(1))
        .expect("fresh apply validates");
    kill_switch::validate(&policy, GenerationId(1)).expect("post-apply validation");
    kill_switch::enforcement_probe(UPLINK_STANDIN).expect("behavioral enforcement proof");

    // 2. ENFORCEMENT, witnessed explicitly: the same uplink-bound
    //    leak probe, with the counter delta asserted here too (the
    //    apply's internal probe already proved it once; this is the
    //    same proof without the apply wrapper).
    let before = kill_switch::dropped_packets().expect("counter readable");
    kill_switch::enforcement_probe(UPLINK_STANDIN).expect("the leak probe is dropped");
    let after = kill_switch::dropped_packets().expect("counter readable");
    assert!(
        after > before,
        "the leak probe was DROPPED by the kill switch ({before} -> {after})"
    );

    // 3. THE LOOPBACK PERMIT: lo traffic must NOT die.
    let listener = UdpSocket::bind("127.0.0.1:0").expect("loopback listener");
    let address = listener.local_addr().expect("bound address");
    let client = UdpSocket::bind("127.0.0.1:0").expect("loopback client");
    client.send_to(b"loopback-probe", address).expect("send");
    listener
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .expect("timeout");
    let mut buffer = [0_u8; 32];
    let (received, _) = listener
        .recv_from(&mut buffer)
        .expect("loopback traffic is permitted through the kill switch");
    assert_eq!(&buffer[..received], b"loopback-probe");

    // 4. ATOMIC RE-APPLY at a new generation with a changed policy
    //    (DHCP permit dropped): one batch, marker moves, rule count
    //    moves with the policy — and the switch STAYS enforced.
    let changed = KillSwitchPolicy {
        allow_dhcp_v4: false,
        ..policy.clone()
    };
    kill_switch::apply(TUN_STANDIN, UPLINK_STANDIN, &changed, GenerationId(2))
        .expect("owned replace validates");
    kill_switch::validate(&changed, GenerationId(2)).expect("generation 2 validated");
    kill_switch::enforcement_probe(UPLINK_STANDIN).expect("still enforced after the replace");

    // 5. OWNED REMOVE: clean; nothing left.
    kill_switch::remove().expect("owned removal");

    // 6. THE LOOKALIKE: a foreign `protonwire` table (no marker) —
    //    apply REFUSES, fails closed, and the foreign table is
    //    intact (never flushed, FR-59).
    let mut foreign = Batch::new();
    let table = Table::new(ProtocolFamily::Inet).with_name("protonwire");
    foreign.add(&table, MsgType::Add);
    foreign.send().expect("the foreign table installs");
    let refusal = kill_switch::apply(TUN_STANDIN, UPLINK_STANDIN, &policy, GenerationId(3))
        .expect_err("a table without our marker is a lookalike");
    assert!(matches!(refusal, KillSwitchError::Lookalike), "{refusal:?}");
    // Intact: still present, and still marker-less (our apply would
    // have added a marker chain and an output chain).
    let present = rustables::list_tables()
        .expect("dump")
        .iter()
        .any(|live| live.get_name().is_some_and(|name| name == "protonwire"));
    assert!(present, "the lookalike was NOT flushed");
    for chain in rustables::list_chains_for_table(&table).expect("chains") {
        if let Some(name) = chain.get_name() {
            assert!(
                GenerationId::from_chain_name(name).is_none() && name != "pw-output",
                "the foreign table carries none of our chains ({name})"
            );
        }
    }

    // Cleanup the foreign table so the namespace ends bare.
    let mut cleanup = Batch::new();
    cleanup.add(&table, MsgType::Del);
    cleanup.send().expect("foreign cleanup");
}

#[test]
fn the_decision_logic_is_pinned() {
    // Belt to the kernel test's braces: the pure decision the live
    // path consults (unit-level, runs everywhere).
    assert_eq!(kill_switch::decide_live(None), ApplyDecision::FreshApply);
    assert_eq!(
        kill_switch::decide_live(Some(&[])),
        ApplyDecision::RefuseLookalike
    );
    assert_eq!(
        kill_switch::decide_live(Some(&[GenerationId(9)])),
        ApplyDecision::ReplaceOwned(GenerationId(9))
    );
}
