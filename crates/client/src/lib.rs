//! Shared unprivileged client SDK (PRD FR-127C/D, ADR-0001).
//!
//! Every first-party client (CLI, TUI, GUI) talks to the daemon exclusively
//! through this crate. It provides typed requests, event subscriptions with
//! missed-event detection, automatic full-state resynchronization, and a
//! stable error surface that maps onto the PRD 9.8 exit codes.
//!
//! This crate must never link ProTUN, Muon, `protonwire-core`, the network
//! adapters, or secure storage — `cargo xtask dep-graph` enforces that.

use std::path::{Path, PathBuf};

use protonwire_frontend_api::{
    ClientInfo, ClientSurface, ConnectTarget, DaemonState, EventEnvelope, Request, RequestResult,
    RpcError, RpcErrorCode, PROTOCOL_VERSION,
};
use protonwire_ipc::{ConnectError, IpcClient, SecurityChecks};

/// Default production socket path (PRD 6.3).
pub const DEFAULT_SOCKET_PATH: &str = "/run/protonwire/protonwire.sock";

/// Environment variable overriding the daemon socket path.
pub const SOCKET_ENV: &str = "PROTONWIRE_SOCKET";

/// Environment variable that disables the root-socket trust checks for
/// development sockets. Never honored implicitly; only set by developers.
pub const DEV_UNSAFE_SOCKET_ENV: &str = "PROTONWIRE_DEV_UNSAFE_SOCKET";

/// Errors surfaced to clients.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The daemon could not be reached.
    #[error("daemon unavailable: {0}")]
    DaemonUnavailable(#[from] ConnectError),
    /// The daemon returned a structured RPC error.
    #[error(transparent)]
    Rpc(RpcError),
    /// A local I/O failure on the client socket.
    #[error("connection to daemon failed: {0}")]
    Io(#[from] std::io::Error),
}

impl ClientError {
    /// The PRD 9.8 exit code for this error.
    pub fn exit_code(&self) -> u8 {
        match self {
            ClientError::DaemonUnavailable(_) => 13,
            ClientError::Rpc(rpc) => rpc_exit_code(rpc.code),
            ClientError::Io(_) => 13,
        }
    }
}

/// Maps RPC codes onto the PRD 9.8 exit-code table.
pub fn rpc_exit_code(code: RpcErrorCode) -> u8 {
    use RpcErrorCode as C;
    match code {
        C::NotImplemented
        | C::InvalidParams
        | C::UnsupportedProtocol
        | C::DaemonBusy
        | C::Internal => 1,
        C::PermissionDenied => 14,
        C::NotAuthenticated => 3,
        C::EntitlementMissing => 4,
        C::NoEligibleServer => 5,
        C::NetworkUnavailable => 6,
        C::TunnelFailed => 7,
        C::KillSwitchFailed => 8,
        C::DnsConfigFailed => 9,
        C::FirewallFailed => 10,
        C::SplitTunnelFailed => 11,
        C::PortForwardingFailed => 12,
        C::ConfigInvalid => 15,
        C::CredentialBackendUnavailable => 16,
        C::SecureCoreUnavailable => 17,
        C::ProtocolUnavailable => 18,
    }
}

/// What the SDK hands to a client's event loop.
#[derive(Debug)]
pub enum ClientEvent {
    /// A daemon event, in order and gap-free since the last delivery.
    Event(EventEnvelope),
    /// Events were missed (daemon restart or slow consumer); a fresh
    /// full-state snapshot was fetched and is included.
    Resynchronized {
        /// The state after resynchronization.
        state: DaemonState,
        /// First sequence number after the gap.
        resumed_at_seq: u64,
    },
}

/// A connected client session with the daemon.
pub struct ProtonwireClient {
    ipc: IpcClient,
    last_seq: Option<u64>,
    surface: ClientSurface,
    name: &'static str,
    version: &'static str,
}

impl ProtonwireClient {
    /// Connects with production defaults: the socket from
    /// [`SOCKET_ENV`] or [`DEFAULT_SOCKET_PATH`], with strict trust checks
    /// (relaxed only when [`DEV_UNSAFE_SOCKET_ENV`] is set).
    pub fn connect_default(surface: ClientSurface) -> Result<Self, ClientError> {
        let path = std::env::var(SOCKET_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH));
        let dev_unsafe = std::env::var(DEV_UNSAFE_SOCKET_ENV).as_deref() == Ok("1");
        let checks = if dev_unsafe {
            SecurityChecks::dev_unchecked()
        } else {
            SecurityChecks::strict()
        };
        Self::connect_to(&path, surface, checks)
    }

    /// Connects to an explicit socket with explicit checks (tests, tooling).
    pub fn connect_to(
        path: &Path,
        surface: ClientSurface,
        checks: SecurityChecks,
    ) -> Result<Self, ClientError> {
        let (name, version) = client_identity();
        let info = ClientInfo {
            name: name.into(),
            version: version.into(),
            surface,
        };
        let ipc = IpcClient::connect(path, &info, checks)?;
        let last_seq = Some(ipc.hello().latest_event_seq);
        Ok(Self {
            ipc,
            last_seq,
            surface,
            name,
            version,
        })
    }

    /// Which client surface this session identifies as.
    pub fn surface(&self) -> ClientSurface {
        self.surface
    }

    /// Daemon version from the handshake.
    pub fn daemon_version(&self) -> &str {
        &self.ipc.hello().daemon_version
    }

    /// Liveness probe.
    pub fn ping(&mut self) -> Result<String, ClientError> {
        match self.ipc.request(Request::Ping { nonce: "ping".into() }) {
            Ok(RequestResult::Pong { nonce }) => Ok(nonce),
            Ok(other) => Err(ClientError::Rpc(RpcError::new(
                RpcErrorCode::Internal,
                format!("unexpected ping result: {other:?}"),
            ))),
            Err(e) => Err(ClientError::Rpc(e)),
        }
    }

    /// Full-state snapshot.
    pub fn state(&mut self) -> Result<DaemonState, ClientError> {
        match self.ipc.request(Request::GetState) {
            Ok(RequestResult::State { state }) => Ok(state),
            Ok(other) => Err(ClientError::Rpc(RpcError::new(
                RpcErrorCode::Internal,
                format!("unexpected state result: {other:?}"),
            ))),
            Err(e) => Err(ClientError::Rpc(e)),
        }
    }

    /// Requests a connection (Milestone 4 implements it server-side).
    pub fn connect_vpn(&mut self, target: ConnectTarget) -> Result<(), ClientError> {
        self.ack(Request::Connect { target })
    }

    /// Requests a disconnect (Milestone 4 implements it server-side).
    pub fn disconnect_vpn(&mut self) -> Result<(), ClientError> {
        self.ack(Request::Disconnect)
    }

    fn ack(&mut self, request: Request) -> Result<(), ClientError> {
        match self.ipc.request(request) {
            Ok(RequestResult::Acknowledged) => Ok(()),
            Ok(other) => Err(ClientError::Rpc(RpcError::new(
                RpcErrorCode::Internal,
                format!("unexpected acknowledgement result: {other:?}"),
            ))),
            Err(e) => Err(ClientError::Rpc(e)),
        }
    }

    /// Blocks for the next event; transparently resynchronizes after a
    /// sequence gap and returns [`ClientEvent::Resynchronized`] instead of
    /// silently losing state (PRD FR-127D).
    pub fn next_event(&mut self) -> Result<ClientEvent, ClientError> {
        let envelope = self.ipc.next_event()?;
        let expected = self.last_seq.map_or(envelope.seq, |last| last + 1);
        if envelope.seq > expected {
            let state = self.state()?;
            self.last_seq = Some(envelope.seq);
            return Ok(ClientEvent::Resynchronized {
                state,
                resumed_at_seq: envelope.seq,
            });
        }
        self.last_seq = Some(envelope.seq);
        Ok(ClientEvent::Event(envelope))
    }

    /// Identity reported by the SDK in the hello handshake.
    pub fn client_identity(&self) -> (&'static str, &'static str, ClientSurface) {
        (self.name, self.version, self.surface)
    }
}

fn client_identity() -> (&'static str, &'static str) {
    ("protonwire-client", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    use protonwire_frontend_api::{Event, NoticeLevel, NetworkIntegration, VpnState};
    use protonwire_ipc::EventBus;

    struct PublishingHandler {
        bus: EventBus,
        seq: AtomicU64,
    }

    impl protonwire_ipc::RequestHandler for PublishingHandler {
        fn daemon_version(&self) -> &str {
            "test-daemon"
        }
        fn latest_event_seq(&self) -> u64 {
            self.seq.load(Ordering::SeqCst)
        }
        fn handle(
            &self,
            _ctx: &protonwire_ipc::SessionContext,
            request: Request,
        ) -> Result<RequestResult, RpcError> {
            match request {
                Request::Ping { nonce } => Ok(RequestResult::Pong { nonce }),
                Request::GetState => Ok(RequestResult::State {
                    state: DaemonState {
                        protocol_version: PROTOCOL_VERSION,
                        daemon_version: "test-daemon".into(),
                        vpn_state: VpnState::Disconnected,
                        network_integration: NetworkIntegration::Auto,
                        active_owner_uid: None,
                    },
                }),
                // Connect bumps the sequence twice but publishes only the
                // second event, simulating a lost event to exercise the
                // client's gap detection.
                Request::Connect { .. } => {
                    let lost = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
                    let used = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
                    debug_assert_eq!(used, lost + 1);
                    self.bus.publish(ServerMessage::Event(EventEnvelope {
                        seq: used,
                        event: Event::StateChanged {
                            from: VpnState::Disconnected,
                            to: VpnState::Connecting,
                        },
                    }));
                    Ok(RequestResult::Acknowledged)
                }
                other => Err(RpcError::new(
                    RpcErrorCode::NotImplemented,
                    format!("{other:?}"),
                )),
            }
        }
        fn event_bus(&self) -> &EventBus {
            &self.bus
        }
    }

    use protonwire_frontend_api::ServerMessage;

    fn spawn_server(dir: &tempfile::TempDir) -> (PathBuf, Arc<PublishingHandler>) {
        let handler = Arc::new(PublishingHandler {
            bus: EventBus::new(),
            seq: AtomicU64::new(0),
        });
        let server =
            protonwire_ipc::server::IpcServer::bind(dir.path(), "sdk.sock").unwrap();
        let path = server.socket_path().to_owned();
        let handler2 = Arc::clone(&handler);
        std::thread::spawn(move || server.serve(handler2, Arc::new(AtomicBool::new(false))));
        (path, handler)
    }

    fn dev_client(path: &Path) -> ProtonwireClient {
        ProtonwireClient::connect_to(path, ClientSurface::Other, SecurityChecks::dev_unchecked())
            .unwrap()
    }

    #[test]
    fn ping_and_state_work_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _handler) = spawn_server(&dir);
        let mut client = dev_client(&path);
        assert_eq!(client.ping().unwrap(), "ping");
        assert_eq!(client.state().unwrap().daemon_version, "test-daemon");
        assert_eq!(client.daemon_version(), "test-daemon");
    }

    #[test]
    fn not_implemented_maps_to_exit_code_one() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _handler) = spawn_server(&dir);
        let mut client = dev_client(&path);
        let err = client.disconnect_vpn().unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(matches!(err, ClientError::Rpc(rpc) if rpc.code == RpcErrorCode::NotImplemented));
    }

    #[test]
    fn sequence_gap_triggers_resync() {
        let dir = tempfile::tempdir().unwrap();
        let (path, handler) = spawn_server(&dir);
        let mut client = dev_client(&path);
        client.connect_vpn(ConnectTarget::Fastest).unwrap();
        // Events 1 (skipped arrival by design) and 2 are in flight; the
        // client sees 2 first because 1 was "lost" — expect a resync.
        match client.next_event().unwrap() {
            ClientEvent::Resynchronized { state, resumed_at_seq } => {
                assert_eq!(resumed_at_seq, 2);
                assert_eq!(state.daemon_version, "test-daemon");
            }
            ClientEvent::Event(envelope) => {
                panic!("expected resync, got event {:?}", envelope.event);
            }
        }
        // After the gap is absorbed, subsequent events flow normally.
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: 3,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "steady".into(),
            },
        }));
        match client.next_event().unwrap() {
            ClientEvent::Event(envelope) => assert_eq!(envelope.seq, 3),
            ClientEvent::Resynchronized { .. } => panic!("unexpected resync"),
        }
    }

    #[test]
    fn missing_daemon_maps_to_exit_thirteen() {
        let err = ProtonwireClient::connect_to(
            Path::new("/nonexistent/protonwire.sock"),
            ClientSurface::Cli,
            SecurityChecks::dev_unchecked(),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 13);
    }
}
