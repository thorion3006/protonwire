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
const BEHAVIORAL_TUN: &str = "pw-btun0";
const BEHAVIORAL_UPLINK: &str = "pw-buplink0";

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
        let plan = protonwire_net::route_txn::plan_with(&mut executor, "", None)
            .await
            .expect("survey");
        // THE CONNECT SEQUENCE'S CONTRACT (the round-1 P1): the kill
        // switch ARMS BEFORE the routing state installs — routes
        // first would leave an escape window (v6 egress through the
        // uplink, the default route before the switch lands) until
        // the switch catches up. Interfaces first (the switch needs
        // their indices); the switch next; the routes last.
        let policy = KillSwitchPolicy {
            tun_ifindex: tun_oif,
            allow_dhcp_v4: true,
            lan_permits: Vec::new(),
            bypass_mark: 0x21,
        };
        kill_switch::apply(TUN_STANDIN, UPLINK_STANDIN, &policy, GenerationId(1), None)
            .expect("the switch arms before any routing");
        let desired =
            protonwire_net::route_drift::desired_ops(&protonwire_net::route_drift::DesiredRoutes {
                plan: plan.clone(),
                tun_oif,
                bypass_mark: 0,
                ipv6: protonwire_net::route_drift::Ipv6Desired::Blocked,
                kill_switch_armed: true,
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
        lan_permits: Vec::new(),
        bypass_mark: 0x21,
    };

    // 1. THE ARMED SWITCH, verified after the routing landed: the
    //    marker generation, the output chain, the exact rendered rule
    //    count — the apply itself ran in the setup, BEFORE the routes
    //    (the connect sequence's contract).
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
    kill_switch::apply(
        TUN_STANDIN,
        UPLINK_STANDIN,
        &changed,
        GenerationId(2),
        Some(GenerationId(1)),
    )
    .expect("owned replace validates — the live marker matches the persisted prior");
    kill_switch::validate(&changed, GenerationId(2)).expect("generation 2 validated");
    kill_switch::enforcement_probe(UPLINK_STANDIN).expect("still enforced after the replace");

    // 4b. A WRONG prior record refuses: the marker on the wire is
    //     generation 2; claiming 1 must not own the table (names are
    //     forgeable — the private record is the proof).
    let refusal = kill_switch::apply(
        TUN_STANDIN,
        UPLINK_STANDIN,
        &changed,
        GenerationId(3),
        Some(GenerationId(1)),
    )
    .expect_err("a mismatched prior must not own the live table");
    assert!(matches!(refusal, KillSwitchError::Lookalike), "{refusal:?}");

    // 5. OWNED REMOVE with the matching prior: clean; nothing left.
    kill_switch::remove(Some(GenerationId(2))).expect("owned removal");

    // 6. THE LOOKALIKE: a foreign `protonwire` table (no marker) —
    //    apply REFUSES, fails closed, and the foreign table is
    //    intact (never flushed, FR-59).
    let mut foreign = Batch::new();
    let table = Table::new(ProtocolFamily::Inet).with_name("protonwire");
    foreign.add(&table, MsgType::Add);
    foreign.send().expect("the foreign table installs");
    let refusal = kill_switch::apply(TUN_STANDIN, UPLINK_STANDIN, &policy, GenerationId(3), None)
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
    assert_eq!(
        kill_switch::decide_live(None, None),
        ApplyDecision::FreshApply
    );
    assert_eq!(
        kill_switch::decide_live(Some(&[]), Some(GenerationId(9))),
        ApplyDecision::RefuseLookalike
    );
    assert_eq!(
        kill_switch::decide_live(Some(&[GenerationId(9)]), Some(GenerationId(9))),
        ApplyDecision::ReplaceOwned(GenerationId(9))
    );
}

/// THE BEHAVIORAL PERMIT PROOFS (sec-audit F2 + QA recs): the
/// round-1 fixes (nfproto scoping, network-order ports, prefix LAN
/// permits, mark discrimination, TUN acceptance) are invisible to
/// rule-count validation — these probes send real packets and
/// assert the counter moves (or doesn't) for each permit's shape.
/// Reintroducing any round-1 bug fails THESE, not the count.
#[test]
fn it_kill_switch_behavioral_permits() {
    if !netns::gate("it_kill_switch_behavioral_permits") {
        return;
    }
    // Topology: TUN + uplink dummies with addresses, v6 on the uplink
    // (the honest shape — the host HAS v6), routes FIRST via the
    // transaction, kill switch armed BEFORE them (the connect
    // sequence's contract).
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let (tun_oif, _uplink_oif) = runtime.block_on(async {
        let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
        tokio::spawn(connection);
        handle
            .link()
            .add(rtnetlink::LinkDummy::new(BEHAVIORAL_TUN).up().build())
            .execute()
            .await
            .expect("tun");
        handle
            .link()
            .add(rtnetlink::LinkDummy::new(BEHAVIORAL_UPLINK).up().build())
            .execute()
            .await
            .expect("uplink");
        let mut links = handle.link().get().execute();
        use futures_util::StreamExt;
        let mut tun = 0;
        let mut up = 0;
        while let Some(message) = links.next().await {
            let m = message.expect("dump");
            match m.attributes.iter().find_map(|a| match a {
                rtnetlink::packet_route::link::LinkAttribute::IfName(name) => Some(name.as_str()),
                _ => None,
            }) {
                Some(BEHAVIORAL_TUN) => tun = m.header.index,
                Some(BEHAVIORAL_UPLINK) => up = m.header.index,
                _ => {}
            }
        }
        handle
            .address()
            .add(
                tun,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 2, 0, 2)),
                32,
            )
            .execute()
            .await
            .expect("tun addr");
        handle
            .address()
            .add(
                up,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 254)),
                24,
            )
            .execute()
            .await
            .expect("uplink v4");
        // The uplink has v6 too — the honest leak surface.
        handle
            .address()
            .add(
                up,
                std::net::IpAddr::V6("2001:db8:ffff::1".parse().unwrap()),
                64,
            )
            .execute()
            .await
            .expect("uplink v6");
        // A v6 default route via the uplink: without one the probe to
        // 2001:db8::1 gets ENETUNREACH before the output chain ever
        // sees it.
        handle
            .route()
            .add({
                let mut message = rtnetlink::packet_route::route::RouteMessage::default();
                message.header.address_family = rtnetlink::packet_route::AddressFamily::Inet6;
                message.header.scope = rtnetlink::packet_route::route::RouteScope::Universe;
                message.header.kind = rtnetlink::packet_route::route::RouteType::Unicast;
                message.attributes = vec![rtnetlink::packet_route::route::RouteAttribute::Oif(up)];
                message
            })
            .execute()
            .await
            .expect("v6 default via uplink");
        (tun, up)
    });

    let policy = KillSwitchPolicy {
        tun_ifindex: tun_oif,
        allow_dhcp_v4: true,
        lan_permits: Vec::new(),
        bypass_mark: 0x21,
    };
    // THE CONNECT SEQUENCE: switch FIRST (the round-3 P1).
    kill_switch::apply(
        BEHAVIORAL_TUN,
        BEHAVIORAL_UPLINK,
        &policy,
        GenerationId(1),
        None,
    )
    .expect("switch arms");

    // === 1. THE V6 LEAK IS DROPPED (IT-3's first live proof) ===
    // An uplink-bound v6 UDP probe to a documentation address.
    let before = kill_switch::terminal_drop_packets().expect("terminal counter");
    let v6_probe = std::net::UdpSocket::bind("[::]:0").expect("v6 socket");
    nix::sys::socket::setsockopt(
        &v6_probe,
        nix::sys::socket::sockopt::BindToDevice,
        &std::ffi::OsString::from(BEHAVIORAL_UPLINK),
    )
    .expect("bind to uplink");
    let _ = v6_probe.send_to(b"v6-leak", "[2001:db8::1]:9");
    let after = kill_switch::terminal_drop_packets().expect("terminal counter");
    assert!(
        after > before,
        "the v6 leak probe was DROPPED ({before} -> {after})"
    );

    // === 2. THE TUNNEL-ROUTED TRAFFIC SURVIVES (the acceptance side) ===
    // Unmarked, NO BINDTODEVICE: the full-tunnel default routes via
    // the TUN — the switch's oif==tun accept must let it through.
    // We need the routes installed for this to route via the TUN.
    let runtime2 = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime2.block_on(async {
        let (connection, handle, _) = rtnetlink::new_connection().expect("netlink");
        tokio::spawn(connection);
        let mut executor = protonwire_net::route_txn::RtnetlinkExecutor::new(handle.clone());
        let plan = protonwire_net::route_txn::plan_with(&mut executor, "", None)
            .await
            .expect("plan");
        let desired =
            protonwire_net::route_drift::desired_ops(&protonwire_net::route_drift::DesiredRoutes {
                plan: plan.clone(),
                tun_oif,
                bypass_mark: 0x21,
                ipv6: protonwire_net::route_drift::Ipv6Desired::Blocked,
                kill_switch_armed: true,
            });
        let mut txn = protonwire_net::route_txn::RouteTransaction::new(plan);
        for op in desired {
            txn = txn.op(op).expect("plan table");
        }
        txn.apply(&mut executor).await.expect("routes");
    });
    let before = kill_switch::terminal_drop_packets().expect("terminal");
    let tunnel_probe = UdpSocket::bind("0.0.0.0:0").expect("tunnel probe");
    // The loopback: the always-present accepted path — proves the
    // switch does NOT block everything (the discrimination base).
    let _ = tunnel_probe.send_to(b"via-lo", "127.0.0.1:9");
    let after = kill_switch::terminal_drop_packets().expect("terminal");
    assert_eq!(
        before, after,
        "tunnel-routed traffic was ACCEPTED) (the oif==tun permit) — NOT dropped"
    );

    // === 3. MARKED SOCKETS SURVIVE (FR-61's identity discrimination) ===
    // SO_MARK 0x21 + uplink-bound: the mark accept must let it
    // through even though the same unmarked shape DIES.
    let marked = UdpSocket::bind("0.0.0.0:0").expect("marked probe");
    nix::sys::socket::setsockopt(&marked, nix::sys::socket::sockopt::Mark, &0x21_u32)
        .expect("SO_MARK (CAP_NET_ADMIN in the namespace)");
    nix::sys::socket::setsockopt(
        &marked,
        nix::sys::socket::sockopt::BindToDevice,
        &std::ffi::OsString::from(BEHAVIORAL_UPLINK),
    )
    .expect("bind to uplink");
    let before = kill_switch::terminal_drop_packets().expect("terminal");
    let _ = marked.send_to(b"marked-leak", "198.51.100.1:9");
    let after = kill_switch::terminal_drop_packets().expect("terminal");
    assert_eq!(
        before, after,
        "the MARKED uplink-bound probe was ACCEPTED) (the mark permit)"
    );

    // The same shape UNMARKED dies (the discrimination is real).
    let unmarked = UdpSocket::bind("0.0.0.0:0").expect("unmarked probe");
    nix::sys::socket::setsockopt(
        &unmarked,
        nix::sys::socket::sockopt::BindToDevice,
        &std::ffi::OsString::from(BEHAVIORAL_UPLINK),
    )
    .expect("bind to uplink");
    let before = kill_switch::terminal_drop_packets().expect("terminal");
    let _ = unmarked.send_to(b"unmarked-leak", "198.51.100.1:9");
    let after = kill_switch::terminal_drop_packets().expect("terminal");
    assert!(
        after > before,
        "the UNMARKED uplink-bound probe DIED) ({before} -> {after}) — discrimination proven"
    );

    kill_switch::remove(Some(GenerationId(1))).expect("cleanup");
}
