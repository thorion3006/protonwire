//! THE M4 exit test (PRD §18, Milestone 4): the full
//! connect/disconnect lifecycle against a MOCKED WireGuard peer,
//! inside the netns harness (NFR-31).
//!
//! The mocked peer is a real boringtun `Tunn` (the SAME WireGuard
//! implementation the tunnel's data plane uses, already in-graph via
//! protun → pvpnclient) bound to a loopback UDP socket: it answers
//! the engine's handshake, the connection reaches `Connected`, stats
//! flow, and the teardown leaves no device behind.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use proton_boringtun::StdTunn;
use proton_boringtun::x25519::{PublicKey, StaticSecret};
use protonwire_net::netns;
use protonwire_protocol::Protocol;
use protonwire_protocol::engine::{
    ConnectionEngine, EngineConfig, EngineConnectionState, EngineEvent, EngineMode, EnginePeerRef,
    EngineTransport, EngineVpnState,
};
use protonwire_protocol::params::{ClientPrivateKey, PeerParams, SniStrategy, TunnelParams};

const IF_NAME: &str = "pwm4exit0";

// Test-side observation of the responder thread (the probe).
static RESPONDER_RECEIVED: AtomicBool = AtomicBool::new(false);
const DEADLINE: Duration = Duration::from_secs(30);

fn key(bytes: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([bytes; 32])
}

/// The mocked WG peer: answers handshakes on one loopback socket
/// ProTUN logs through the `log` facade; without a logger those lines
/// vanish. Same harness rule as it_engine_lifecycle: stderr, never
/// above Debug.
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
fn install_logger() {
    INSTALL_LOGGER.call_once(|| {
        let _ = log::set_logger(&StderrLogger);
        log::set_max_level(log::LevelFilter::Debug);
    });
}
/// until `stop`. Returns its public key (base64) and address.
fn spawn_mocked_peer(stop: Arc<AtomicBool>) -> (String, SocketAddr) {
    let mut server_key = [0u8; 32];
    getrandom::fill(&mut server_key).expect("server key entropy");
    let server_secret = StaticSecret::from(server_key);
    let server_public = PublicKey::from(&server_secret);

    // The CLIENT's fixed key (the engine side mirrors it below); the
    // responder must know it to complete the handshake.
    let client_secret = StaticSecret::from([0x7A; 32]);
    let client_public = PublicKey::from(&client_secret);

    let socket =
        std::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
            .expect("bind the mocked peer");
    let address = socket.local_addr().expect("peer address");
    let public_base64 = base64::engine::general_purpose::STANDARD.encode(server_public.as_bytes());

    std::thread::spawn(move || {
        let mut env = proton_boringtun::StdEnv::default();
        let mut tunnel = StdTunn::new(
            server_secret,
            client_public,
            None,
            None,
            0x5151_0002,
            None,
            &mut env,
        );
        let mut buf = [0u8; 1500];
        let mut out = [0u8; 2048];
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("peer read timeout");
        while !stop.load(Ordering::Relaxed) {
            let Ok((len, peer)) = socket.recv_from(&mut buf) else {
                continue; // read timeout: poll the stop flag
            };
            eprintln!("[m4-peer] received {len} bytes from {peer}");
            RESPONDER_RECEIVED.store(true, Ordering::Relaxed);
            // decapsulate answers handshakes/messages; per its
            // contract a WriteToNetwork is followed by
            // empty-datagram calls until Done (queued packets drain).
            if let proton_boringtun::noise::TunnResult::WriteToNetwork(bytes) =
                tunnel.decapsulate(None, &buf[..len], &mut out)
            {
                eprintln!("[m4-peer] answering {} bytes", bytes.len());
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

#[test]
fn m4_exit_connect_disconnect_lifecycle() {
    install_logger();
    if !netns::gate("M4 exit: connect/disconnect against the mocked WG peer") {
        return;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let (peer_public, peer_addr) = spawn_mocked_peer(Arc::clone(&stop));

    // Loopback probe: a plain UDP datagram must reach the responder
    // before the engine enters the picture (isolates netns/lo from
    // the engine socket path).
    {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let address = peer_addr;
        probe.send_to(b"probe", address).expect("probe send");
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            if RESPONDER_RECEIVED.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            RESPONDER_RECEIVED.load(Ordering::Relaxed),
            "the loopback probe never reached the mocked peer (lo is down in this namespace?)"
        );
        eprintln!("[m4-exit] loopback probe received");
    }

    let params = TunnelParams {
        peers: vec![PeerParams {
            id: "m4-exit-peer".to_owned(),
            entry_ip: peer_addr.ip(),
            public_key_base64: peer_public,
            udp_ports: vec![peer_addr.port()],
            tcp_ports: Vec::new(),
            tls_ports: Vec::new(),
            priority: 1,
            exit_label: Some("m4-exit".to_owned()),
        }],
        protocol: Protocol::WireGuardUdp,
        network_available: true,
        client_private_key: Some(ClientPrivateKey::new(key(0x7A))),
        sni_strategy: SniStrategy::Random,
    };

    let engine = ConnectionEngine::new(EngineConfig {
        if_name: IF_NAME.to_owned(),
        bypass_mark: 0x51820,
        mode: EngineMode::NoLocalAgent,
    });
    let mut connection = engine
        .connect(&params, Box::new(protonwire_protocol::NullCache::default()))
        .expect("the engine starts against the mocked peer");

    // THE milestone line: the handshake completes against the real
    // WireGuard implementation — Connected, with the deterministic
    // peer, transport, and port the engine chose.
    let connected = {
        let start = Instant::now();
        loop {
            if start.elapsed() > DEADLINE {
                panic!("no Connected state within {DEADLINE:?}");
            }
            match connection.events().recv_timeout(Duration::from_millis(200)) {
                Ok(EngineEvent::State(EngineVpnState {
                    connection: EngineConnectionState::Connected { peer, .. },
                    ..
                })) => break peer,
                Ok(_) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(other) => panic!("event channel died: {other:?}"),
            }
        }
    };
    assert_eq!(
        connected,
        EnginePeerRef {
            peer_id: "m4-exit-peer".to_owned(),
            entry_ip: peer_addr.ip(),
            protocol: EngineTransport::WireGuardUdp,
            port: peer_addr.port(),
        }
    );

    // Stats flow over the live session (FR-30's pull).
    connection.request_stats();
    let stats_seen = {
        let start = Instant::now();
        loop {
            if start.elapsed() > DEADLINE {
                break false;
            }
            match connection.events().recv_timeout(Duration::from_millis(200)) {
                Ok(EngineEvent::Stats(_)) => break true,
                Ok(_) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => break false,
            }
        }
    };
    assert!(stats_seen, "the live session answers a stats pull");

    // The mark seam held for the whole session (FR-32B live).
    assert!(connection.mark_health().healthy());

    // Teardown: the device dies with the connection (FR-24/31).
    connection.disconnect();
    assert!(nix::net::if_::if_nametoindex(IF_NAME).is_err());

    stop.store(true, Ordering::Relaxed);
}
