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
    RpcError, RpcErrorCode,
};
use protonwire_ipc::{ConnectError, IpcClient, RequestError, SecurityChecks};

/// Re-export so clients never need a direct protonwire-ipc dependency.
pub use protonwire_ipc::SecurityChecks as IpcSecurityChecks;

/// Default production socket path (PRD 6.3).
pub const DEFAULT_SOCKET_PATH: &str = "/run/protonwire/protonwire.sock";

/// Environment variable overriding the daemon socket path.
pub const SOCKET_ENV: &str = "PROTONWIRE_SOCKET";

/// Environment variable that disables the root-socket trust checks for
/// development sockets. Honored **only in debug builds**; release builds
/// always perform the full checks.
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
        C::NotImplemented | C::UnsupportedProtocol | C::DaemonBusy | C::Internal => 1,
        C::InvalidParams => 2,
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

/// Maps an IPC transport failure onto the client error surface: a broken
/// or unresponsive daemon connection is exit 13 (PRD 9.8), with a
/// reconnect instruction, not a generic exit 1.
fn transport_failure(message: String) -> ClientError {
    ClientError::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        message,
    ))
}

impl ProtonwireClient {
    /// Connects with production defaults: the socket from
    /// [`SOCKET_ENV`] or [`DEFAULT_SOCKET_PATH`], with strict trust checks.
    ///
    /// [`DEV_UNSAFE_SOCKET_ENV`] relaxes the trust checks only in debug
    /// builds (`cfg!(debug_assertions)`); release builds always verify the
    /// root-owned socket and root daemon peer. Tests and tooling that need
    /// the relaxation in release builds pass
    /// [`IpcSecurityChecks::dev_unchecked()`] explicitly via
    /// [`ProtonwireClient::connect_to`].
    pub fn connect_default(surface: ClientSurface) -> Result<Self, ClientError> {
        let path = std::env::var(SOCKET_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH));
        Self::connect_to(&path, surface, security_checks_from_env())
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

    /// Overrides the request timeout (tests use short values).
    pub fn set_request_timeout(&mut self, timeout: std::time::Duration) {
        self.ipc.set_timeout(timeout);
    }

    /// Liveness probe.
    pub fn ping(&mut self) -> Result<String, ClientError> {
        match self.ipc.request(Request::Ping {
            nonce: "ping".into(),
        }) {
            Ok(RequestResult::Pong { nonce }) => Ok(nonce),
            Ok(other) => Err(ClientError::Rpc(RpcError::new(
                RpcErrorCode::Internal,
                format!("unexpected ping result: {other:?}"),
            ))),
            Err(RequestError::Rpc(rpc)) => Err(ClientError::Rpc(rpc)),
            Err(RequestError::Transport(message)) => Err(transport_failure(message)),
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
            Err(RequestError::Rpc(rpc)) => Err(ClientError::Rpc(rpc)),
            Err(RequestError::Transport(message)) => Err(transport_failure(message)),
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

    /// Requests a daemon shutdown. The daemon serves this only to
    /// administrator (UID 0) peers; other callers receive a
    /// `PermissionDenied` RPC error.
    pub fn shutdown_daemon(&mut self) -> Result<(), ClientError> {
        self.ack(Request::Shutdown)
    }

    fn ack(&mut self, request: Request) -> Result<(), ClientError> {
        match self.ipc.request(request) {
            Ok(RequestResult::Acknowledged) => Ok(()),
            Ok(other) => Err(ClientError::Rpc(RpcError::new(
                RpcErrorCode::Internal,
                format!("unexpected acknowledgement result: {other:?}"),
            ))),
            Err(RequestError::Rpc(rpc)) => Err(ClientError::Rpc(rpc)),
            Err(RequestError::Transport(message)) => Err(transport_failure(message)),
        }
    }

    /// Blocks for the next event; transparently resynchronizes after a
    /// sequence gap and returns [`ClientEvent::Resynchronized`] instead of
    /// silently losing state (PRD FR-127D). Stale or duplicate sequence
    /// numbers (daemon restart, reordering) are skipped without rewinding
    /// the cursor (rust-review finding 9).
    pub fn next_event(&mut self) -> Result<ClientEvent, ClientError> {
        loop {
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
            if envelope.seq < expected {
                // Already seen: drop it and keep waiting. Delivering it
                // would rewind the cursor and make the next genuine event
                // look like a gap.
                continue;
            }
            self.last_seq = Some(envelope.seq);
            return Ok(ClientEvent::Event(envelope));
        }
    }

    /// Identity reported by the SDK in the hello handshake.
    pub fn client_identity(&self) -> (&'static str, &'static str, ClientSurface) {
        (self.name, self.version, self.surface)
    }
}

fn client_identity() -> (&'static str, &'static str) {
    ("protonwire-client", env!("CARGO_PKG_VERSION"))
}

/// The single trust-check policy (refactorer step 3): the development
/// bypass requires BOTH a debug build and the env flag; release builds
/// always run strict checks. Pure so the policy is unit-testable —
/// edition 2024 makes `std::env::set_var` unsafe and the workspace denies
/// `unsafe_code`, so the env read stays in the caller.
pub fn checks_for(dev_flag: Option<&str>, debug_build: bool) -> IpcSecurityChecks {
    if debug_build && dev_flag == Some("1") {
        IpcSecurityChecks::dev_unchecked()
    } else {
        IpcSecurityChecks::strict()
    }
}

/// Resolves the trust checks from [`DEV_UNSAFE_SOCKET_ENV`] for the
/// current build. Honored in debug builds only.
pub fn security_checks_from_env() -> IpcSecurityChecks {
    checks_for(
        std::env::var(DEV_UNSAFE_SOCKET_ENV).ok().as_deref(),
        cfg!(debug_assertions),
    )
}

/// Connects with an optional socket override and the SDK check policy.
///
/// This is the connection entry point apps should use: it resolves the
/// `PROTONWIRE_SOCKET` override and the (debug-only) bypass in one place,
/// so clients never assemble the policy themselves.
pub fn connect_with_socket_override(
    socket: Option<&Path>,
    surface: ClientSurface,
) -> Result<ProtonwireClient, ClientError> {
    match socket {
        Some(path) => {
            let path = std::env::var(SOCKET_ENV)
                .map(PathBuf::from)
                .unwrap_or_else(|_| path.to_owned());
            ProtonwireClient::connect_to(&path, surface, security_checks_from_env())
        }
        None => ProtonwireClient::connect_default(surface),
    }
}

#[cfg(test)]
mod checks_tests {
    use super::*;

    /// The trust-bypass policy, pinned across its full input space so the
    /// three former copies (SDK, CLI, TUI) cannot drift apart again
    /// (refactorer step 3).
    #[test]
    fn dev_bypass_requires_both_debug_build_and_flag() {
        let cases = [
            (Some("1"), true, false), // debug + flag → bypass
            (Some("1"), false, true), // release + flag → strict
            (None, true, true),       // debug, no flag → strict
            (Some("0"), true, true),  // wrong flag value → strict
            (Some("2"), true, true),  // any non-"1" → strict
            (None, false, true),      // release, nothing → strict
        ];
        for (flag, debug, expect_strict) in cases {
            let checks = checks_for(flag, debug);
            assert_eq!(
                checks.require_root_socket, expect_strict,
                "flag={flag:?} debug={debug}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use protonwire_frontend_api::{
        Event, NetworkIntegration, NoticeLevel, PROTOCOL_VERSION, ServerMessage, VpnState,
    };
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

    fn spawn_server(
        dir: &tempfile::TempDir,
    ) -> (
        protonwire_ipc::test_util::TestServer,
        Arc<PublishingHandler>,
    ) {
        let handler = Arc::new(PublishingHandler {
            bus: EventBus::new(),
            seq: AtomicU64::new(0),
        });
        let server = protonwire_ipc::test_util::TestServer::start(
            dir.path(),
            "sdk.sock",
            Arc::clone(&handler),
        )
        .expect("test server binds");
        (server, handler)
    }

    fn dev_client(path: &Path) -> ProtonwireClient {
        ProtonwireClient::connect_to(path, ClientSurface::Other, SecurityChecks::dev_unchecked())
            .unwrap()
    }

    #[test]
    fn ping_and_state_work_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let (server, _handler) = spawn_server(&dir);
        let path = server.socket_path().to_owned();
        let mut client = dev_client(&path);
        assert_eq!(client.ping().unwrap(), "ping");
        assert_eq!(client.state().unwrap().daemon_version, "test-daemon");
        assert_eq!(client.daemon_version(), "test-daemon");
    }

    #[test]
    fn not_implemented_maps_to_exit_code_one() {
        let dir = tempfile::tempdir().unwrap();
        let (server, _handler) = spawn_server(&dir);
        let path = server.socket_path().to_owned();
        let mut client = dev_client(&path);
        let err = client.disconnect_vpn().unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(matches!(err, ClientError::Rpc(rpc) if rpc.code == RpcErrorCode::NotImplemented));
    }

    #[test]
    fn sequence_gap_triggers_resync() {
        let dir = tempfile::tempdir().unwrap();
        let (server, handler) = spawn_server(&dir);
        let path = server.socket_path().to_owned();
        let mut client = dev_client(&path);
        client.connect_vpn(ConnectTarget::Fastest).unwrap();
        // Events 1 (skipped arrival by design) and 2 are in flight; the
        // client sees 2 first because 1 was "lost" — expect a resync.
        match client.next_event().unwrap() {
            ClientEvent::Resynchronized {
                state,
                resumed_at_seq,
            } => {
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

    /// Regression (rust-review finding 9): a stale or duplicate sequence
    /// number must be skipped, never delivered and never allowed to rewind
    /// the cursor (a rewind makes the next genuine event look like a gap
    /// and triggers a spurious resync).
    #[test]
    fn stale_events_are_skipped_without_rewinding() {
        let dir = tempfile::tempdir().unwrap();
        let (server, handler) = spawn_server(&dir);
        let path = server.socket_path().to_owned();
        let mut client = dev_client(&path);

        let publish = |seq: u64, message: &str| {
            handler.bus.publish(ServerMessage::Event(EventEnvelope {
                seq,
                event: Event::Notice {
                    level: NoticeLevel::Info,
                    message: message.into(),
                },
            }));
        };

        publish(1, "fresh");
        match client.next_event().unwrap() {
            ClientEvent::Event(envelope) => assert_eq!(envelope.seq, 1),
            ClientEvent::Resynchronized { .. } => panic!("unexpected resync"),
        }

        // A stale duplicate (already-seen seq) arrives, then a fresh event.
        publish(1, "stale duplicate");
        publish(2, "fresh after stale");
        match client.next_event().unwrap() {
            ClientEvent::Event(envelope) => {
                assert_eq!(envelope.seq, 2, "stale event must be skipped");
                let notice = match envelope.event {
                    Event::Notice { message, .. } => message,
                    other => panic!("expected notice, got {other:?}"),
                };
                assert_eq!(notice, "fresh after stale");
            }
            ClientEvent::Resynchronized { .. } => panic!("stale event must not trigger resync"),
        }
    }

    #[test]
    fn missing_daemon_maps_to_exit_thirteen() {
        let err = ProtonwireClient::connect_to(
            Path::new("/nonexistent/protonwire.sock"),
            ClientSurface::Cli,
            IpcSecurityChecks::dev_unchecked(),
        )
        .err()
        .expect("connect must fail without a daemon");
        assert_eq!(err.exit_code(), 13);
    }

    /// Rust-review findings 4+5 (M1.1 redesign): a daemon that completes
    /// the handshake but never answers a request is a TRANSPORT failure —
    /// exit 13 (daemon unavailable), not exit 1 (generic) — and after such
    /// a failure the client must fail fast with a reconnect instruction
    /// instead of silently retrying a desynchronized stream.
    #[test]
    fn unresponsive_daemon_is_transport_failure_and_poisons_the_client() {
        use std::os::unix::net::UnixListener;
        use std::time::Instant;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("silent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            // Complete the handshake, then swallow every request forever.
            let _ = protonwire_ipc::frame::read_msg::<_, protonwire_frontend_api::ClientMessage>(
                &mut peer,
            );
            let _ = protonwire_ipc::frame::write_msg(
                &mut peer,
                &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                    protocol_version: 1,
                    daemon_version: "silent".into(),
                    latest_event_seq: 0,
                }),
            );
            while protonwire_ipc::frame::read_msg::<_, protonwire_frontend_api::ClientMessage>(
                &mut peer,
            )
            .is_ok()
            {}
        });

        let mut client = ProtonwireClient::connect_to(
            &path,
            ClientSurface::Other,
            IpcSecurityChecks::dev_unchecked(),
        )
        .unwrap();
        client.set_request_timeout(std::time::Duration::from_millis(150));

        let started = Instant::now();
        let err = client.state().expect_err("silent daemon must fail");
        assert_eq!(
            err.exit_code(),
            13,
            "transport failure is daemon-unavailable"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));

        // The poisoned client fails fast on the next call.
        let started = Instant::now();
        let err = client.state().expect_err("poisoned client must fail");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(err.exit_code(), 13);
        assert!(
            err.to_string().to_lowercase().contains("reconnect"),
            "poisoned error should instruct a reconnect, got: {err}"
        );
    }

    /// The full RPC-code → exit-code table against PRD 9.8, so a silent
    /// mapping rot fails here instead of in a user's script.
    #[test]
    fn rpc_exit_code_table_matches_prd_9_8() {
        use RpcErrorCode as C;
        let table = [
            (C::NotImplemented, 1u8),
            (C::InvalidParams, 2),
            (C::NotAuthenticated, 3),
            (C::EntitlementMissing, 4),
            (C::NoEligibleServer, 5),
            (C::NetworkUnavailable, 6),
            (C::TunnelFailed, 7),
            (C::KillSwitchFailed, 8),
            (C::DnsConfigFailed, 9),
            (C::FirewallFailed, 10),
            (C::SplitTunnelFailed, 11),
            (C::PortForwardingFailed, 12),
            (C::DaemonBusy, 1),
            (C::UnsupportedProtocol, 1),
            (C::ConfigInvalid, 15),
            (C::CredentialBackendUnavailable, 16),
            (C::SecureCoreUnavailable, 17),
            (C::ProtocolUnavailable, 18),
            (C::Internal, 1),
            (C::PermissionDenied, 14),
        ];
        for (code, expected) in table {
            assert_eq!(
                rpc_exit_code(code),
                expected,
                "wrong exit code for {code:?}"
            );
        }
    }
}
