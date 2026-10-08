//! IT: the session orchestrator end-to-end (netns-gated, NFR-31).
//! The full connect→verify→disconnect cycle: kill switch arms
//! before routes, DNS applies, the enforcement probe passes, and
//! disconnect reverts everything. This is IT-13's composition
//! surface (the sequencing proof) and the M5 exit's integration
//! test.

use protonwire_net::dns::{DnsConfig, DnsMode, DnsRouting};
use protonwire_net::kill_switch::GenerationId;
use protonwire_net::netns;
use protonwire_net::route_drift::Ipv6Desired;
use protonwire_net::route_txn::{NetlinkExecutor, RtnetlinkExecutor};
use protonwire_net::session::{self, ConnectInputs};

#[tokio::test]
async fn it_session_lifecycle() {
    if !netns::gate("it_session_lifecycle") {
        return;
    }
    let (connection, handle, _) = rtnetlink::new_connection().expect("netlink connection");
    tokio::spawn(connection);
    let mut executor = RtnetlinkExecutor::new(handle.clone());

    // Topology: TUN + uplink dummies (same as the kill-switch IT).
    use futures_util::StreamExt;
    handle
        .link()
        .add(rtnetlink::LinkDummy::new("pw-tun0").up().build())
        .execute()
        .await
        .expect("tun");
    handle
        .link()
        .add(rtnetlink::LinkDummy::new("pw-uplink0").up().build())
        .execute()
        .await
        .expect("uplink");
    let mut links = handle.link().get().execute();
    let mut tun_ifindex = 0;
    let mut uplink_ifindex = 0;
    while let Some(message) = links.next().await {
        let m = message.expect("dump");
        match m.attributes.iter().find_map(|a| match a {
            rtnetlink::packet_route::link::LinkAttribute::IfName(name) => {
                Some(name.as_str().to_owned())
            }
            _ => None,
        }) {
            Some(ref n) if n == "pw-tun0" => tun_ifindex = m.header.index,
            Some(ref n) if n == "pw-uplink0" => uplink_ifindex = m.header.index,
            _ => {}
        }
    }
    assert!(tun_ifindex > 0 && uplink_ifindex > 0, "interfaces exist");

    // Addresses (without a source on the uplink, the probe gets EINVAL).
    handle
        .address()
        .add(
            tun_ifindex,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 2, 0, 2)),
            32,
        )
        .execute()
        .await
        .expect("tun addr");
    handle
        .address()
        .add(
            uplink_ifindex,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 254)),
            24,
        )
        .execute()
        .await
        .expect("uplink addr");

    let kill_policy = protonwire_net::kill_switch::KillSwitchPolicy {
        tun_ifindex,
        allow_dhcp_v4: false,
        lan_permits: Vec::new(),
        bypass_mark: 0x21,
    };

    let inputs = ConnectInputs {
        tun_ifindex,
        tun_ifname: "pw-tun0".into(),
        uplink_ifname: "pw-uplink0".into(),
        bypass_mark: 0x21,
        ipv6: Ipv6Desired::Blocked,
        dns: DnsConfig {
            mode: DnsMode::Proton,
            servers: vec![protonwire_net::dns::DnsServer::new(
                "10.2.0.1".parse().unwrap(),
            )],
            routing: DnsRouting::ThroughVpn,
        },
        generation: GenerationId(1),
        prior_generation: None,
        persisted_tables: None,
    };

    // === CONNECT (the full sequence: kill switch → routes → DNS) ===
    let state = session::connect(&mut executor, "", &inputs, &kill_policy)
        .await
        .expect("the full connect sequence");

    // VERIFY: the kill switch is enforced (the probe already ran
    // inside apply; this is the external re-check).
    protonwire_net::kill_switch::enforcement_probe("pw-uplink0")
        .expect("the switch is still enforced after connect returns");

    // VERIFY: the routes are present.
    let survey = executor.survey("").await.expect("post-connect survey");
    assert!(
        survey.occupied.contains(
            &state
                .plan
                .assignment(protonwire_net::tables::TableKind::Main)
                .id
        ),
        "the plan's main table is occupied by the session's routes"
    );

    // === DISCONNECT (the inverse: DNS → routes → switch) ===
    session::disconnect(
        &mut executor,
        &state,
        "pw-tun0",
        false,
        Some(GenerationId(1)),
    )
    .await
    .expect("the full disconnect sequence");

    // VERIFY: the switch is gone.
    assert!(
        protonwire_net::kill_switch::dropped_packets().is_err(),
        "the kill switch table is gone after disconnect"
    );

    // VERIFY: the routes are gone.
    let survey = executor.survey("").await.expect("post-disconnect survey");
    for id in state.plan.ids() {
        assert!(
            !survey.occupied.contains(&id),
            "plan table {id} unreferenced after disconnect"
        );
    }
}
