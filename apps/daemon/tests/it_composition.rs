//! IT-32: the daemon's connection LANE end-to-end in a network
//! namespace (NFR-31) — the M6 1b composition proof. The lane
//! composes the engine (agentless, against the same mocked
//! WireGuard peer the M4 exit uses) with the M5 session orchestrator:
//! startup allocates the bypass mark against the live namespace,
//! connect health-gates the engine's marks BEFORE the route commit
//! (IT-13's ordering, structural in `compose_net_session` and
//! behaviorally proven here by a fully-established session), the
//! kill switch arms, routes commit, the handshake completes against
//! the peer, and disconnect reverts everything in the M5 inverse
//! order. This is the milestone's "the daemon actually connects"
//! line.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use protonwire_core::state::{DaemonCore, EventSink};
use protonwire_frontend_api::{EventEnvelope, VpnState};
use protonwire_net::dns::{DnsConfig, DnsMode, DnsRouting};
use protonwire_net::kill_switch;
use protonwire_net::netns;
use protonwire_net::route_drift::Ipv6Desired;
use protonwire_protocol::engine::{EngineMode, EngineVpnState};
use protonwire_protocol::params::{
    ClientPrivateKey, PeerParams, SniStrategy, TransportEndpoint, TunnelParams,
};
use protonwire_protocol::{PersistenceFacade, Protocol};

use protonwire_daemon::connect::ConnectionLane;
use protonwire_daemon::netctx::NetContext;

const UPLINK: &str = "pw-comp-uplink";
const TUN: &str = "pw-comp-tun";

struct CollectingSink(std::sync::Mutex<Vec<EventEnvelope>>);
impl EventSink for CollectingSink {
    fn publish(&self, event: EventEnvelope) {
        self.0.lock().expect("sink").push(event);
    }
}

/// ProTUN logs through the `log` facade — surface them on stderr for
/// this IT (the m4-exit harness's pattern: never above Debug).
struct StderrLogger;
impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("[protun] {}", record.args());
        }
    }
    fn flush(&self) {}
}
static INSTALL_LOGGER: std::sync::Once = std::sync::Once::new();

/// The peer-side answer to the engine's CONNECTION PROBE (protun
/// v3.0.5 pings through the tunnel; Connected waits for the echo):
/// an IPv4 ICMP echo REQUEST becomes its REPLY — type 0, addresses
/// swapped, both checksums recomputed. `None` for anything else.
fn icmp_echo_reply(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 1 {
        return None; // not IPv4/ICMP
    }
    if packet[20] != 8 {
        return None; // not an echo request
    }
    let mut reply = packet.to_vec();
    // Swap the IP addresses (bytes 12..16 and 16..20).
    reply.swap_range(12, 16, 16, 20);
    reply[20] = 0; // echo reply
    // ICMP checksum (offset 22..24) over the whole ICMP message, zeroed first.
    reply[22] = 0;
    reply[23] = 0;
    let sum: u32 = reply[20..]
        .chunks(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32)
        .sum();
    let checksum = !(sum + (sum >> 16)) as u16;
    reply[22..24].copy_from_slice(&checksum.to_be_bytes());
    // IP header checksum (offset 10..12) over the 20-byte header.
    reply[10] = 0;
    reply[11] = 0;
    let sum: u32 = reply[..20]
        .chunks(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]) as u32)
        .sum();
    let checksum = !(sum + (sum >> 16)) as u16;
    reply[10..12].copy_from_slice(&checksum.to_be_bytes());
    Some(reply)
}

trait SwapRange {
    fn swap_range(&mut self, a: usize, b: usize, c: usize, d: usize);
}
impl SwapRange for Vec<u8> {
    fn swap_range(&mut self, a: usize, b: usize, c: usize, d: usize) {
        for (left, right) in (a..b).zip(c..d) {
            self.swap(left, right);
        }
    }
}

/// The mocked WireGuard responder (the M4-exit pattern, ported): a
/// real boringtun `Tunn` answering handshakes on one loopback socket.
fn spawn_mocked_peer(stop: Arc<AtomicBool>) -> (String, std::net::SocketAddr) {
    use proton_boringtun::noise::Tunn;
    use proton_boringtun::proton_os_interface::lock::Loose;
    use proton_boringtun::proton_os_interface::time::Instant as OsInstant;
    use proton_boringtun::proton_os_interface::time::SinceUnixEpoch as _;
    use proton_boringtun::proton_os_interface::time::SystemTime as OsSystemTime;
    use proton_boringtun::rand::SeedableRng;
    use proton_boringtun::rand::rngs::StdRng;
    use proton_boringtun::x25519::{PublicKey, StaticSecret};

    use base64::Engine as _;
    let mut server_key = [0u8; 32];
    getrandom::fill(&mut server_key).expect("server key entropy");
    let server_secret = StaticSecret::from(server_key);
    let server_public = PublicKey::from(&server_secret);
    let client_public = PublicKey::from(&StaticSecret::from([0x7A_u8; 32])); // the engine side mirrors it

    let socket = std::net::UdpSocket::bind(std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        0,
    ))
    .expect("bind the mocked peer");
    let address = socket.local_addr().expect("peer address");
    let public_base64 = base64::engine::general_purpose::STANDARD.encode(server_public.as_bytes());

    std::thread::spawn(move || {
        let epoch = std::time::Instant::now();
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("wall clock after the epoch");
        let mut rng_seed = <StdRng as SeedableRng>::Seed::default();
        getrandom::fill(&mut rng_seed).expect("responder RNG entropy");
        let mut tunnel: Tunn<StdRng, Loose> = Tunn::new(
            server_secret,
            client_public,
            None,
            None,
            0x5252_0002,
            None,
            OsInstant::from_duration(epoch.elapsed()),
            OsSystemTime::since_unix_epoch(unix),
            StdRng::from_seed(rng_seed),
        );
        let mut buf = [0u8; 1500];
        let mut out = [0u8; 2048];
        let mut out2 = [0u8; 2048];
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("peer read timeout");
        // The last peer we answered — timer-fired writes (keepalives,
        // retransmits) go there; before any packet arrives there is
        // nowhere to send.
        let mut last_peer: Option<std::net::SocketAddr> = None;
        while !stop.load(Ordering::Relaxed) {
            // TIMERS FIRST, ON EVERY WAKE-UP (packet OR timeout — the
            // pure-Tunn contract): the private rate limiter resets ONLY
            // here, and skipping the timeout iterations left it stale —
            // the engine's retry bursts then read as under-load and the
            // responder dropped them (the flake).
            if let proton_boringtun::noise::TunnResult::WriteToNetwork(bytes) =
                tunnel.update_timers(&mut out, OsInstant::from_duration(epoch.elapsed()))
                && let Some(peer) = last_peer
            {
                let _ = socket.send_to(bytes, peer);
            }
            let Ok((len, peer)) = socket.recv_from(&mut buf) else {
                continue;
            };
            last_peer = Some(peer);
            // The connection probe: decapsulated IP packets that are
            // ICMP echo requests get their REPLY encapsulated back —
            // Connected waits for it (protun v3.0.5).
            if let proton_boringtun::noise::TunnResult::WriteToTunnelV4(packet, _addr) =
                tunnel.decapsulate(None, &buf[..len], &mut out)
            {
                if let Some(reply) = icmp_echo_reply(packet)
                    && let proton_boringtun::noise::TunnResult::WriteToNetwork(bytes) =
                        tunnel.encapsulate(&reply, &mut out2)
                {
                    let _ = socket.send_to(bytes, peer);
                }
                continue;
            }
            if let proton_boringtun::noise::TunnResult::WriteToNetwork(bytes) =
                tunnel.decapsulate(None, &buf[..len], &mut out)
            {
                let _ = socket.send_to(bytes, peer);
                while let proton_boringtun::noise::TunnResult::WriteToNetwork(bytes) =
                    tunnel.decapsulate(None, &[], &mut out)
                {
                    let _ = socket.send_to(bytes, peer);
                }
            }
        }
    });
    (public_base64, address)
}

/// Waits for the core's latest VPN state to become `want` (the pump
/// publishes asynchronously). On timeout, dumps the sink's event
/// stream — the diagnosis for a wedged or stale pump.
fn await_state(core: &DaemonCore, sink: &CollectingSink, want: VpnState) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if core.state().vpn_state == want {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let events: Vec<String> = sink
        .0
        .lock()
        .expect("sink")
        .iter()
        .map(|envelope| format!("{:?}", envelope.event))
        .collect();
    panic!(
        "the core never reached {want:?} (now {:?}); events so far:\n{}",
        core.state().vpn_state,
        events.join("\n")
    );
}

#[test]
fn it32_the_lane_composes_engine_and_net_session() {
    if !netns::gate("it32: the daemon lane composes engine ∘ net session") {
        return;
    }
    INSTALL_LOGGER.call_once(|| {
        let _ = log::set_logger(&StderrLogger);
        log::set_max_level(log::LevelFilter::Debug);
    });
    // The runtime the NetContext and its netlink connection live on.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("test runtime");

    // Topology: the uplink dummy with an address and a DEFAULT ROUTE
    // (detect_uplink's fixture — the kill switch's uplink). The
    // connection construction AND the spawn run inside block_on (a
    // reactor must be active at both points).
    {
        use futures_util::StreamExt;
        let _handle = runtime.block_on(async {
            let (connection, handle, _) = rtnetlink::new_connection().expect("netlink");
            tokio::spawn(connection);
            handle
                .link()
                .add(rtnetlink::LinkDummy::new(UPLINK).up().build())
                .execute()
                .await
                .expect("uplink");
            let mut links = handle.link().get().execute();
            let mut uplink_ifindex = 0;
            while let Some(message) = links.next().await {
                let m = message.expect("dump");
                for attribute in &m.attributes {
                    if let rtnetlink::packet_route::link::LinkAttribute::IfName(name) = attribute
                        && name == UPLINK
                    {
                        uplink_ifindex = m.header.index;
                    }
                }
            }
            assert!(uplink_ifindex > 0, "the uplink exists");
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
            handle
        });
        // The fixture's DEFAULT ROUTE via `ip` (the harness's own
        // fixture tool — the lo-up shim's precedent; the raw-message
        // encoding subtleties are the writer's domain, not the
        // fixture's).
        let status = std::process::Command::new("ip")
            .args(["route", "add", "default", "via", "192.0.2.1", "dev", UPLINK])
            .status()
            .expect("spawn ip");
        assert!(status.success(), "the default route installs");
    }

    // STARTUP: the mark allocation runs against the LIVE namespace.
    let net = NetContext::startup(
        runtime.handle().clone(),
        TUN.to_owned(),
        DnsConfig {
            mode: DnsMode::None, // no /etc mutation from the harness
            servers: vec![],
            routing: DnsRouting::ThroughVpn,
        },
        Ipv6Desired::Blocked,
    )
    .expect("the net context starts (mark allocated)");
    assert_ne!(net.mark, 0);
    assert_eq!(net.uplink_ifname.as_deref(), Some(UPLINK), "detect_uplink");

    // The core + the facade (a temp cache with a fixed test key — the
    // engine is agentless; the cache only carries the WG keys).
    let sink = Arc::new(CollectingSink(std::sync::Mutex::new(Vec::new())));
    let core = Arc::new(DaemonCore::new(
        "0.1.0-it",
        Arc::new(protonwire_store::config::SystemConfig::default()),
        sink.clone(),
    ));
    let dir = std::env::temp_dir().join(format!("pw-it32-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("cache dir");
    let cache = Arc::new(
        protonwire_protocol::EncryptedCache::with_key_bytes(&dir, &[7u8; 32]).expect("cache"),
    );
    let facade = Arc::new(PersistenceFacade::start(cache));

    let lane = Arc::new(ConnectionLane::new_with_mode(
        net,
        EngineMode::NoLocalAgent,
        facade,
        Arc::clone(&core),
    ));

    // The peer + the params (the engine side mirrors the responder's
    // fixed client key).
    let stop = Arc::new(AtomicBool::new(false));
    let (peer_public, peer_addr) = spawn_mocked_peer(Arc::clone(&stop));
    let key = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode([0x7A_u8; 32])
    };
    let params = TunnelParams {
        peers: vec![PeerParams {
            id: "it32-peer".to_owned(),
            public_key_base64: peer_public,
            udp: Some(TransportEndpoint {
                entry_ip: peer_addr.ip(),
                ports: vec![peer_addr.port()],
            }),
            tcp: None,
            tls: None,
            priority: 1,
            exit_label: Some("it32".to_owned()),
            server_name: None, // the loopback peer has no certificate
        }],
        protocol: Protocol::WireGuardUdp,
        network_available: true,
        client_private_key: Some(ClientPrivateKey::new(key)),
        sni_strategy: SniStrategy::Random,
    };

    // === CONNECT through the LANE (uid 1000): engine ∘ session ===
    lane.connect(1000, &params).expect("the lane connects");
    await_state(&core, &sink, VpnState::Connected);
    assert_eq!(core.state().active_owner_uid, Some(1000));
    // The session composed: the switch is enforced and probe-able on
    // the uplink, and routes occupy the planned tables.
    kill_switch::enforcement_probe(UPLINK).expect("the switch is armed");

    // A second UID is refused typed (the owner gate through the lane).
    let refused = lane.connect(2000, &params).unwrap_err();
    assert!(
        matches!(
            refused,
            protonwire_daemon::connect::LaneError::Refused(
                protonwire_daemon::connect::LaneRefusal::NotOwner { owner: 1000 }
            )
        ),
        "the owner gate refuses cross-UID: {refused:?}"
    );

    // === DISCONNECT: the M5 inverse (DNS → routes → switch) then the
    // engine teardown; the core lands Disconnected and the switch is
    // gone. ===
    lane.disconnect(1000).expect("the lane disconnects");
    await_state(&core, &sink, VpnState::Disconnected);
    assert_eq!(core.state().active_owner_uid, None);
    assert!(
        kill_switch::enforcement_probe(UPLINK).is_err(),
        "the switch is removed after disconnect"
    );

    stop.store(true, Ordering::Relaxed);
    lane.drain();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A compile-time pin that the events the pump maps are the frontend
/// vocabulary (the IT's await_state reads `state().vpn`).
#[allow(dead_code)]
fn vpn_state_shape(state: &EngineVpnState) -> VpnState {
    protonwire_daemon::connect::map_vpn_state(state)
}
