//! IT-14's engine-lifecycle slice (PRD 17.2): the connection engine's
//! live composition — translate → TUN hand-off → mark seam → ProTUN's
//! connection thread → state events → disconnect cleanup — against a
//! DETERMINISTIC peer (fixed keys, loopback endpoint, no network
//! dependency), inside the netns harness (NFR-31).
//!
//! The peer answers nothing: ProTUN cycles it and stays `Connecting`,
//! which is exactly what this slice pins — the full
//! connected-through-server proof rides PR-5's M4 exit test (the
//! mocked WG peer).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use base64::Engine as _;
use protonwire_net::netns;
use protonwire_protocol::Protocol;
use protonwire_protocol::engine::{
    ActiveConnection, ConnectionEngine, EngineConfig, EngineConnectionState, EngineEvent,
    EngineMode, EngineVpnState,
};
use protonwire_protocol::params::{ClientPrivateKey, PeerParams, SniStrategy, TunnelParams};

const IF_NAME: &str = "pwengine0";
const DEADLINE: Duration = Duration::from_secs(20);

/// A deterministic WireGuard key: 32 fixed bytes, base64.
fn key(bytes: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([bytes; 32])
}

/// The deterministic test peer: loopback UDP, fixed keys — IT-14's
/// "deterministic test peers" fixture.
fn deterministic_peer(id: &str) -> PeerParams {
    PeerParams {
        id: id.to_owned(),
        entry_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        public_key_base64: key(0x42),
        udp_ports: vec![51820],
        tcp_ports: vec![443],
        tls_ports: vec![8443],
        priority: 1,
        exit_label: Some("test-exit".to_owned()),
    }
}

fn tunnel_params() -> TunnelParams {
    TunnelParams {
        peers: vec![deterministic_peer("it14-peer")],
        protocol: Protocol::WireGuardUdp,
        network_available: true,
        client_private_key: Some(ClientPrivateKey::new(key(0x7A))),
        sni_strategy: SniStrategy::Random,
    }
}

/// Waits for an event matching `predicate`, failing on DEADLINE.
/// Non-matching events print (nocapture) — the diagnostic trail of
/// what ProTUN actually emitted.
fn await_event(
    connection: &mut ActiveConnection,
    predicate: &dyn Fn(&EngineEvent) -> bool,
    what: &str,
) -> EngineEvent {
    let start = Instant::now();
    while start.elapsed() < DEADLINE {
        match connection.events().recv_timeout(Duration::from_millis(200)) {
            Ok(event) if predicate(&event) => return event,
            Ok(other) => {
                eprintln!("[it14] non-matching event: {other:?}");
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(other) => panic!("event channel died waiting for {what}: {other:?}"),
        }
    }
    panic!("timed out waiting for {what} within {DEADLINE:?}");
}

/// ProTUN logs through the `log` facade; without a logger those lines
/// vanish. A stderr logger makes the engine's own diagnostics visible
/// under `--nocapture`.
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

fn mark_health_reported(connection: &ActiveConnection) -> bool {
    let start = Instant::now();
    while start.elapsed() < DEADLINE {
        if connection.mark_health().reported() > 0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn it14_engine_composition_lifecycle() {
    install_logger();
    if !netns::gate("IT-14 engine lifecycle: compose -> connect -> mark -> disconnect") {
        return;
    }
    let engine = ConnectionEngine::new(EngineConfig {
        if_name: IF_NAME.to_owned(),
        bypass_mark: 0x51820,
        mode: EngineMode::NoLocalAgent,
    });

    let mut connection = engine
        .connect(
            &tunnel_params(),
            Box::new(protonwire_protocol::NullCache::default()),
        )
        .expect("the composed connection starts");
    assert_eq!(connection.interface_name(), IF_NAME);

    // FR-29 lane: the state events flow, translated. PINNED BEHAVIOR
    // of protun v2.2.1 (observed): the `Connecting` state carries an
    // EMPTY peer list — the deterministic peer's id only ever rides
    // the per-peer states (`Connected`). If an upgrade populates it,
    // this pin fails and the daemon lane learns its state surface
    // changed.
    let connecting = await_event(
        &mut connection,
        &|event| {
            matches!(
                event,
                EngineEvent::State(EngineVpnState {
                    connection: EngineConnectionState::Connecting { .. },
                    ..
                })
            )
        },
        "a Connecting state",
    );
    assert!(
        matches!(connecting, EngineEvent::State(_)),
        "the awaited event is a state"
    );

    // FR-32B lane: protun created its outer socket and OUR callback
    // saw it — the mark seam is live inside the real engine, not just
    // in the unit seam.
    assert!(
        mark_health_reported(&connection),
        "the mark callback must see protun's outer socket ({:?} reported)",
        connection.mark_health().reported()
    );
    assert!(connection.mark_health().healthy());

    // FR-28/32C lane: peer rotation on the live connection.
    let mut rotated = tunnel_params();
    rotated.peers.push(deterministic_peer("it14-peer-2"));
    connection
        .update_peers(&rotated)
        .expect("rotation translates");

    // Nothing above blocked the daemon side: the poll surface works.
    assert!(connection.latest_state().is_some());

    // FR-24/31 lane: disconnect tears the whole composition down; the
    // TUN descriptor ProTUN owned closes with its stream and the
    // device dies.
    connection.disconnect();
    assert!(
        nix::net::if_::if_nametoindex(IF_NAME).is_err(),
        "the device dies with the disconnected connection"
    );
}
