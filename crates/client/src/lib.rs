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
    ClientInfo, ClientSurface, ConnectTarget, DaemonState, EVENT_SEQ_RESYNC_NOW, EventEnvelope,
    Request, RequestResult, RpcError, RpcErrorCode,
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
        // M2 S2 additions: PRD 9.8 has no dedicated slots for the
        // auth/refresh failure modes, so they map to the general error
        // until the S9 client surface assigns any it owns; persistence
        // unhealthy IS the credential-backend slot's semantics.
        C::UpstreamCapabilityBlocked
        | C::UnsupportedChallenge
        | C::ConfirmationRequired
        | C::RateLimited => 1,
        C::CredentialPersistenceUnhealthy => 16,
    }
}

/// What the SDK hands to a client's event loop.
#[derive(Debug)]
pub enum ClientEvent {
    /// A daemon event, in order and gap-free since the last delivery.
    Event(EventEnvelope),
    /// Events were missed (daemon restart or slow consumer); a fresh
    /// full-state snapshot was fetched and is included. The daemon's
    /// reserved overflow marker — a burst that ended on a drop while this
    /// client lagged (X4) — surfaces here too, with no gap event involved.
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
    /// The cursor: the seq of the last event actually DELIVERED to the
    /// client's stream (or, after a resync, the seq the snapshot covers).
    /// `None` until the first delivery — the hello stamp is NOT a
    /// delivery, so it never seeds this (S14, FR-127D: the session
    /// subscribes before the stamp is read, and events buffered in that
    /// window sit at or below the stamp; a stamp-seeded cursor classified
    /// them stale and silently dropped them).
    last_seq: Option<u64>,
    /// The hello ack's `latest_event_seq` — the daemon's newest seq at
    /// handshake time. Not a delivery; it is the FLOOR for gap detection
    /// until the first delivery initializes the cursor: a first forwarded
    /// seq already beyond `stamp + 1` means events between the stamp and
    /// it were lost before this client subscribed, which is the same
    /// miss the stamp exists to detect.
    hello_seq: u64,
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
        let path = resolve_socket_path(None, std::env::var(SOCKET_ENV).ok().as_deref());
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
        // S14 (FR-127D): the cursor does NOT seed from the ack stamp.
        // The daemon's session subscribes to the event bus BEFORE the
        // stamp is read, so events buffered in that window are forwarded
        // at or below the stamp — a stamp-seeded cursor classified them
        // stale on arrival and silently dropped them. Deliver-then-
        // advance instead: the cursor stays uninitialized until the first
        // delivery; the stamp is kept only as the gap-detection floor
        // (see [`ProtonwireClient::next_event`]).
        let hello_seq = ipc.hello().latest_event_seq;
        Ok(Self {
            ipc,
            last_seq: None,
            hello_seq,
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
    ///
    /// The cursor advances ONLY on a delivery (or a loud snapshot
    /// resync) — deliver-then-advance (S14, FR-127D): until the first
    /// delivery initializes it, the hello stamp acts as the gap-detection
    /// floor and nothing else. A first forwarded seq at or below
    /// `stamp + 1` is DELIVERED — the daemon's session subscribes before
    /// the stamp is read, so pre-hello-buffered events legitimately sit
    /// at or below the stamp, and the pre-fix stamp-seeded cursor
    /// silently dropped exactly those. A first seq beyond `stamp + 1`
    /// means events between the stamp and it were lost before this
    /// client subscribed — the same miss the stamp exists to detect —
    /// and resynchronizes.
    ///
    /// The snapshot is paired with its own sequence (Codex PR review round
    /// 2, finding 1): `GetState` is a separate request, so events published
    /// while it was in flight are already reflected in the returned state.
    /// The cursor advances to the snapshot's stamped sequence (falling back
    /// to the gap event on daemons that do not stamp), and buffered events
    /// the snapshot covers are dropped — replaying them after the newer
    /// snapshot would regress the client's view.
    ///
    /// Ordering caveat for callers composing this with
    /// [`ProtonwireClient::state`]: pre-hello-window events — delivered
    /// first by the rule above — may predate a snapshot `state()` fetched
    /// before the window drained. The snapshot reflects the daemon's
    /// CURRENT state, so it is strictly newer than those buffered events;
    /// applying them onto it would regress the view. Callers using both
    /// surfaces should compare each event's seq against
    /// `state.latest_event_seq` and skip what the snapshot already covers.
    ///
    /// The daemon's reserved marker envelope (seq
    /// [`EVENT_SEQ_RESYNC_NOW`], X4) is intercepted BEFORE the gap logic
    /// and never delivered as an event: it is the daemon's explicit
    /// end-of-burst overflow signal — events were dropped while this
    /// client lagged and no later seq is coming to reveal the gap — so it
    /// triggers the same resynchronization immediately. The marker's seq
    /// must never enter the cursor: it is unmatchable by design, and a
    /// cursor holding it would swallow or gap-trigger on every subsequent
    /// real event.
    pub fn next_event(&mut self) -> Result<ClientEvent, ClientError> {
        loop {
            let envelope = self.ipc.next_event()?;
            if envelope.seq == EVENT_SEQ_RESYNC_NOW {
                // No gap seq exists for the marker — the daemon did not
                // say WHICH events were dropped, only that some were. The
                // snapshot's stamp is the cursor (the fallback keeps the
                // current cursor on an unstamped daemon instead of
                // rewinding it into a spurious-gap state).
                return self.resynchronize(None);
            }
            let expected = match self.last_seq {
                Some(last) => match last.checked_add(1) {
                    Some(next) => next,
                    // checked_add (rust-review round 8): a pre-signal SDK
                    // that stored the reserved marker's seq sits at
                    // u64::MAX; overflow means resynchronize — no SDK
                    // build panics on cursor arithmetic.
                    None => return self.resynchronize(None),
                },
                None => {
                    // S14 deliver-then-advance: the first delivery
                    // initializes the cursor, whatever its seq — the
                    // hello stamp is a floor, not a delivery, so a
                    // pre-hello-buffered event at or below it is
                    // delivered instead of classified stale. Only a
                    // first seq beyond the floor (stamp + 1, checked —
                    // a stamp AT the reserved marker value cannot be
                    // exceeded by any real seq, so overflow means the
                    // gap branch is vacuously false) resynchronizes.
                    if self
                        .hello_seq
                        .checked_add(1)
                        .is_some_and(|floor| envelope.seq > floor)
                    {
                        return self.resynchronize(Some(envelope.seq));
                    }
                    self.last_seq = Some(envelope.seq);
                    return Ok(ClientEvent::Event(envelope));
                }
            };
            if envelope.seq > expected {
                return self.resynchronize(Some(envelope.seq));
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

    /// The shared resynchronization tail (PRD FR-127D): fetch a fresh
    /// snapshot, advance the cursor past everything it covers, drop the
    /// buffered events it already reflects, and report the recovery.
    ///
    /// `gap_seq` is the seq that revealed the miss — the first event after
    /// the gap, or `None` for the daemon's reserved marker, which carries
    /// no real seq by construction. The cursor lands on the snapshot's
    /// stamp (falling back to the revealing seq, or the current cursor
    /// for the marker path), floored at that fallback so a lagging stamp
    /// can never rewind the cursor below what the client has seen.
    fn resynchronize(&mut self, gap_seq: Option<u64>) -> Result<ClientEvent, ClientError> {
        let state = self.state()?;
        let fallback = gap_seq.unwrap_or_else(|| self.last_seq.unwrap_or(0));
        let cursor = state.latest_event_seq.unwrap_or(fallback).max(fallback);
        self.ipc.discard_events_through(cursor);
        self.last_seq = Some(cursor);
        Ok(ClientEvent::Resynchronized {
            state,
            resumed_at_seq: cursor,
        })
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

/// Resolves the daemon socket path (Codex PR review finding 6): an explicit
/// `--socket` flag wins, then `PROTONWIRE_SOCKET`, then the documented
/// default. Pure so the precedence is unit-testable — the env read stays in
/// the callers because edition 2024 makes `set_var` unsafe and the workspace
/// denies `unsafe_code` (same seam as [`checks_for`]).
pub fn resolve_socket_path(socket: Option<&Path>, env_override: Option<&str>) -> PathBuf {
    match socket {
        Some(path) => path.to_owned(),
        None => env_override
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH)),
    }
}

/// Connects with an optional socket override and the SDK check policy.
///
/// This is the connection entry point apps should use: it resolves the
/// `--socket` flag and `PROTONWIRE_SOCKET` (flag wins — see
/// [`resolve_socket_path`]) plus the (debug-only) bypass in one place, so
/// clients never assemble the policy themselves.
pub fn connect_with_socket_override(
    socket: Option<&Path>,
    surface: ClientSurface,
) -> Result<ProtonwireClient, ClientError> {
    let path = resolve_socket_path(socket, std::env::var(SOCKET_ENV).ok().as_deref());
    ProtonwireClient::connect_to(&path, surface, security_checks_from_env())
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
                        latest_event_seq: Some(self.seq.load(Ordering::SeqCst)),
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

    /// QA S14 round (P2-1, mutation C): the Some-arm mid-stream gap
    /// branch had zero post-S14 coverage — every gap fixture entered
    /// through the None arm (a FIRST delivery beyond the hello floor) or
    /// the reserved overflow marker, so deleting the Some-arm resync
    /// passed the whole suite. Here the cursor is seeded by contiguous
    /// deliveries first (1..=3, each exactly the expected next seq), and
    /// only then does a gap arrive: seq 5 with NO marker after the
    /// client was left expecting 4. The Some arm must fire — a LOUD
    /// resync, never a silent delivery of the gap event as contiguous.
    /// Mutation evidence: deleting the `envelope.seq > expected` resync
    /// turns the second phase into exactly that silent delivery and this
    /// test red; recorded in the fix commit's message.
    #[test]
    fn mid_stream_gap_after_seeding_resyncs_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let (server, handler) = spawn_server(&dir);
        let path = server.socket_path().to_owned();
        let mut client = dev_client(&path);
        // Handshake stamps seq 0, so the client expects event 1 next.

        // Seed the cursor with contiguous deliveries: events 1, 2, 3.
        for seq in 1..=3u64 {
            handler.seq.store(seq, Ordering::SeqCst);
            handler.bus.publish(ServerMessage::Event(EventEnvelope {
                seq,
                event: Event::Notice {
                    level: NoticeLevel::Info,
                    message: format!("contiguous {seq}"),
                },
            }));
            match client.next_event().unwrap() {
                ClientEvent::Event(envelope) => assert_eq!(envelope.seq, seq),
                ClientEvent::Resynchronized { .. } => {
                    panic!("contiguous event {seq} must deliver, not resync")
                }
            }
        }

        // The mid-stream gap: event 4 is never published; 5 arrives with
        // no marker while the cursor holds Some(3), so expected = 4 and
        // 5 > expected — the Some arm.
        handler.seq.store(5, Ordering::SeqCst);
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: 5,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "gap event".into(),
            },
        }));
        match client.next_event().unwrap() {
            ClientEvent::Resynchronized {
                state,
                resumed_at_seq,
            } => {
                // The resync snapshot is stamped 5 (the daemon's newest
                // seq), so the cursor lands ON the gap event's seq: the
                // client has seen up to 5 through the snapshot.
                assert_eq!(resumed_at_seq, 5);
                assert_eq!(state.latest_event_seq, Some(5));
            }
            ClientEvent::Event(envelope) => panic!(
                "the mid-stream gap event {} was delivered as contiguous — \
                 a lost event vanished silently (Some-arm resync deleted?)",
                envelope.seq
            ),
        }

        // Exactly once per the resync contract: the gap event 5 is
        // accounted for by the snapshot and never replayed as an Event,
        // and the next delivery is the first event BEYOND the snapshot —
        // a cursor left anywhere else would either resync again or
        // swallow 6 as stale.
        handler.seq.store(6, Ordering::SeqCst);
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: 6,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "after the gap".into(),
            },
        }));
        match client.next_event().unwrap() {
            ClientEvent::Event(envelope) => assert_eq!(envelope.seq, 6),
            ClientEvent::Resynchronized { .. } => panic!("unexpected second resync"),
        }
    }

    /// rust-review round 8 (Medium): a pre-signal SDK that stored the
    /// reserved marker's seq leaves the cursor at u64::MAX; the next
    /// normal event then hit `last + 1` — a debug panic one add away.
    /// checked_add turns the overflow into a resynchronization.
    #[test]
    fn poisoned_cursor_resynchronizes_instead_of_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let (server, handler) = spawn_server(&dir);
        let path = server.socket_path().to_owned();
        let mut client = dev_client(&path);
        client.last_seq = Some(u64::MAX);
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: 7,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "after poison".into(),
            },
        }));
        match client.next_event().unwrap() {
            ClientEvent::Resynchronized { resumed_at_seq, .. } => {
                assert_eq!(resumed_at_seq, u64::MAX);
            }
            ClientEvent::Event(envelope) => panic!(
                "expected a resync from the poisoned cursor, got event {}",
                envelope.seq
            ),
        }
    }

    /// X4 (round 8): when a burst of events overflows the daemon-side
    /// session queue (the round-1 retain-on-Full design) and the burst
    /// ENDS there, the drop is invisible — no later seq arrives, so the
    /// client's gap detection never fires and it holds stale state
    /// indefinitely. The daemon must signal the overflow WITHOUT a
    /// subsequent real publish: the client below never reads during the
    /// burst (so the session's queue provably fills and drops), the burst
    /// then stops, and after a grace period the client's `next_event`
    /// must surface a resynchronization on its own — a bounded watchdog
    /// turns the pre-fix indefinite silence into a failure.
    #[test]
    fn end_of_burst_overflow_reaches_the_client_without_a_later_publish() {
        use std::time::{Duration, Instant};

        // Sized so the burst provably overflows every buffer on the fan-out
        // path while the client is not reading: socket send buffer (~MiBs at
        // the most per message below) + writer channel (256) + session queue
        // (256). 32 KiB payloads keep the socket-buffer share of the
        // capacity at a handful-hundred messages on any default Linux
        // wmem, so 1024 events cannot fit and the tail is dropped.
        const PAYLOAD: usize = 32 * 1024;
        const BURST: u64 = 1024;
        // Generous overall watchdog: the green path only has to drain what
        // was buffered (tens of MiB in-process), but a loaded CI machine
        // gets room; the RED failure mode is the watchdog tripping after
        // the client has gone silent past its own per-call timeouts.
        const WATCHDOG: Duration = Duration::from_secs(20);

        let dir = tempfile::tempdir().unwrap();
        let (server, handler) = spawn_server(&dir);
        let path = server.socket_path().to_owned();
        let mut client = dev_client(&path);
        // Short per-call timeout so an idle (pre-fix) `next_event` returns
        // TimedOut quickly instead of blocking the watchdog out; still
        // enough for the resync's GetState to read past the backlog.
        client.set_request_timeout(Duration::from_millis(500));

        // The burst: publish while the client is NOT reading. The session
        // queue fills, the tail is dropped, the burst stops there.
        let notice = "x".repeat(PAYLOAD);
        for seq in 1..=BURST {
            handler.seq.store(seq, Ordering::SeqCst);
            handler.bus.publish(ServerMessage::Event(EventEnvelope {
                seq,
                event: Event::Notice {
                    level: NoticeLevel::Info,
                    message: notice.clone(),
                },
            }));
        }
        assert_eq!(
            handler.seq.load(Ordering::SeqCst),
            BURST,
            "fixture sanity: the daemon's newest seq is the burst end"
        );
        // Grace: let the forwarder/writer settle into their blocked state
        // before the client starts draining.
        std::thread::sleep(Duration::from_millis(200));

        // No further publish happens below until the client has learned.
        let deadline = Instant::now() + WATCHDOG;
        let mut delivered = 0u64;
        let mut recovery = None;
        while recovery.is_none() {
            assert!(
                Instant::now() < deadline,
                "client never learned the end-of-burst overflow: {delivered} \
                 events delivered, then silence — the drop is invisible \
                 without a later publish (X4)"
            );
            match client.next_event() {
                Ok(ClientEvent::Event(_)) => delivered += 1,
                Ok(resync @ ClientEvent::Resynchronized { .. }) => recovery = Some(resync),
                Err(ClientError::Io(io))
                    if io.kind() == std::io::ErrorKind::TimedOut
                        || io.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    continue; // "no event yet": re-poll inside the watchdog
                }
                Err(other) => panic!("unexpected failure while draining: {other}"),
            }
        }
        // The recovery was self-sufficed: the snapshot is stamped with the
        // burst's END — the seq of events the client provably never saw.
        match recovery.expect("the watchdog loop only exits with a recovery") {
            ClientEvent::Resynchronized {
                state,
                resumed_at_seq,
            } => {
                assert_eq!(resumed_at_seq, BURST);
                assert_eq!(state.latest_event_seq, Some(BURST));
            }
            ClientEvent::Event(envelope) => {
                panic!("expected a resync, got event {:?}", envelope.event)
            }
        }
        assert!(
            delivered < BURST,
            "the burst tail was dropped, so the client cannot have seen every \
             event; {delivered} were delivered before the signal"
        );

        // Post-recovery checks — after the client has learned, NOT triggers
        // for it: the overflowed session kept its subscription...
        assert_eq!(
            handler.bus.session_count(),
            1,
            "retain-on-Full: the overflowed session must stay subscribed"
        );
        // ...the cursor is a real seq (not poisoned by the signal), so the
        // next genuine event flows without another resync.
        handler.seq.store(BURST + 1, Ordering::SeqCst);
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: BURST + 1,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "after recovery".into(),
            },
        }));
        match client.next_event().unwrap() {
            ClientEvent::Event(envelope) => assert_eq!(envelope.seq, BURST + 1),
            ClientEvent::Resynchronized { .. } => {
                panic!("post-recovery events must flow without another resync")
            }
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

    /// FR-127D / round-9 severity-bar disposition (M2 S14): the session
    /// subscribes to the event bus at ACCEPT — before the hello ack's
    /// `latest_event_seq` stamp is read — so events published in that
    /// window are BOTH buffered for the client AND at or below the stamp.
    /// The pre-fix cursor seeded itself from the stamp (`Some(stamp)`),
    /// so every pre-hello-buffered event classified as stale on arrival
    /// and was silently discarded: the daemon forwarded it, the client's
    /// event stream never saw it, and `next_event` went on waiting as if
    /// nothing had happened.
    ///
    /// The handler reproduces the window deterministically: the real
    /// server stamps the ack from `latest_event_seq()` (session.rs), so
    /// publishing INSIDE that call guarantees the events are queued (the
    /// session subscribed at accept, long before hello) before the stamp
    /// is read by the same call. The hello gate holds them until after
    /// the ack (WO-5), so the wire order is ack first, then the window's
    /// events — exactly the pre-hello-buffered shape.
    struct PreHelloWindowHandler {
        bus: EventBus,
        /// `(seq, message)` pairs published inside the stamp call, in
        /// order. The reserved marker seq may appear among them to
        /// interleave an X4 signal into the window.
        window: &'static [(u64, &'static str)],
    }

    impl PreHelloWindowHandler {
        /// The daemon's newest REAL seq — side-effect free, so GetState
        /// can stamp without re-publishing. The marker's reserved MAX
        /// never models the daemon's progress and is excluded.
        fn stamp(&self) -> u64 {
            self.window
                .iter()
                .map(|&(seq, _)| seq)
                .filter(|&seq| seq != EVENT_SEQ_RESYNC_NOW)
                .max()
                .unwrap_or(0)
        }
    }

    impl protonwire_ipc::RequestHandler for PreHelloWindowHandler {
        fn daemon_version(&self) -> &str {
            "test-daemon"
        }
        fn latest_event_seq(&self) -> u64 {
            for &(seq, message) in self.window {
                self.bus.publish(ServerMessage::Event(EventEnvelope {
                    seq,
                    event: Event::Notice {
                        level: NoticeLevel::Info,
                        message: message.into(),
                    },
                }));
            }
            self.stamp()
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
                        latest_event_seq: Some(self.stamp()),
                    },
                }),
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

    /// S14 deliver-then-advance pin (the exactly-once invariant, part 1 —
    /// the pre-hello window): EVERY event the daemon forwarded reaches
    /// the client's event stream exactly once. Here events 1 and 2 are
    /// forwarded while both sit at or below the ack stamp 2 — the
    /// pre-fix code silently dropped both and then blocked on an empty
    /// queue until timeout.
    #[test]
    fn pre_hello_buffered_events_are_delivered_not_dropped() {
        let window: &'static [(u64, &'static str)] = &[(1, "buffered one"), (2, "buffered two")];
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(PreHelloWindowHandler {
            bus: EventBus::new(),
            window,
        });
        let server = protonwire_ipc::test_util::TestServer::start(
            dir.path(),
            "pre-hello.sock",
            Arc::clone(&handler),
        )
        .expect("test server binds");
        let path = server.socket_path().to_owned();
        let mut client = dev_client(&path);
        // Short timeout so the pre-fix silent drop fails fast instead of
        // hanging: both forwarded events are swallowed as "stale" and
        // `next_event` is left waiting on an empty stream.
        client.set_request_timeout(std::time::Duration::from_millis(300));

        for (seq, message) in window {
            match client.next_event().unwrap() {
                ClientEvent::Event(envelope) => {
                    assert_eq!(envelope.seq, *seq);
                    match envelope.event {
                        Event::Notice { message: got, .. } => assert_eq!(got, *message),
                        other => panic!("expected notice, got {other:?}"),
                    }
                }
                ClientEvent::Resynchronized { .. } => {
                    panic!("a pre-hello-buffered event is not a gap: seq {seq}")
                }
            }
        }

        // Beyond the stamp the stream continues gap-free — the seeded
        // state must not manufacture a spurious resync either.
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: 3,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "after the stamp".into(),
            },
        }));
        match client.next_event().unwrap() {
            ClientEvent::Event(envelope) => assert_eq!(envelope.seq, 3),
            ClientEvent::Resynchronized { .. } => panic!("unexpected resync"),
        }
    }

    /// S14 pin (the exactly-once invariant, part 2 — a marker
    /// interleaving): the daemon's reserved X4 marker inside the
    /// pre-hello window must be intercepted BEFORE any cursor
    /// arithmetic — in the pinned scenario the cursor holds a DELIVERED
    /// seq (1) below the snapshot stamp (2). The marker never reaches
    /// the stream as an Event, its unmatchable seq never enters the
    /// cursor, and the recovery is LOUD: a resync whose snapshot
    /// accounts for the window's remaining buffered events, so nothing
    /// the daemon forwarded vanishes silently. (The interception itself
    /// is cursor-state-independent — the reserved-seq check precedes the
    /// cursor match — but an earlier draft of this comment claimed the
    /// pin covered the marker arriving "while the cursor is still
    /// uninitialized". It does not, and that state is
    /// production-unreachable: the forwarder emits the marker only
    /// AFTER forwarding a real event (session.rs `forward_events`), and
    /// the writer's FIFO hands the SDK that real event — initializing
    /// the cursor, by delivery or by the floor resync — before the
    /// marker. Claim corrected in the S14 review round per the round-2
    /// precedent.)
    #[test]
    fn marker_interleaved_in_the_pre_hello_window_resyncs_loudly() {
        let window: &'static [(u64, &'static str)] = &[
            (1, "buffered one"),
            (
                EVENT_SEQ_RESYNC_NOW,
                "event queue overflowed; resynchronize",
            ),
            (2, "buffered two"),
        ];
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(PreHelloWindowHandler {
            bus: EventBus::new(),
            window,
        });
        let server = protonwire_ipc::test_util::TestServer::start(
            dir.path(),
            "pre-hello-marker.sock",
            Arc::clone(&handler),
        )
        .expect("test server binds");
        let path = server.socket_path().to_owned();
        let mut client = dev_client(&path);
        client.set_request_timeout(std::time::Duration::from_millis(300));

        // The window opens with a real delivery: event 1 initializes the
        // cursor (deliver-then-advance), even though it sits below the
        // stamp 2.
        match client.next_event().unwrap() {
            ClientEvent::Event(envelope) => assert_eq!(envelope.seq, 1),
            ClientEvent::Resynchronized { .. } => {
                panic!("the first forwarded event must be delivered, not resynced past")
            }
        }

        // The interleaved marker: a loud resync, never an Event, with the
        // cursor landing on the snapshot's stamp 2 — the reserved seq
        // must not poison it.
        match client.next_event().unwrap() {
            ClientEvent::Resynchronized {
                state,
                resumed_at_seq,
            } => {
                assert_eq!(
                    resumed_at_seq, 2,
                    "the marker's reserved seq must never enter the cursor"
                );
                assert_eq!(state.latest_event_seq, Some(2));
            }
            ClientEvent::Event(envelope) => {
                panic!("the reserved marker surfaced as an event: {envelope:?}")
            }
        }

        // Buffered event 2 was discarded as snapshot-covered by the loud
        // resync above; the first event BEYOND the stamp flows with no
        // spurious gap — proving the cursor holds the real seq 2, not MAX.
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: 3,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "after the marker".into(),
            },
        }));
        match client.next_event().unwrap() {
            ClientEvent::Event(envelope) => assert_eq!(envelope.seq, 3),
            ClientEvent::Resynchronized { .. } => panic!("unexpected resync after the marker"),
        }
    }

    /// Codex PR review round 2, finding 1 (P2): the resync snapshot is a
    /// SEPARATE `GetState` request, so events published while it is in
    /// flight are already reflected in the snapshot the response carries.
    /// Pre-fix, the SDK reset its cursor to the gap event's sequence and
    /// replayed those buffered older events AFTER the newer snapshot —
    /// regressing the client's displayed state. The daemon now stamps the
    /// snapshot with its own sequence; the SDK must advance the cursor to
    /// that stamp and drop buffered events the snapshot already covers.
    #[test]
    fn resync_snapshot_advances_the_cursor_to_its_own_sequence() {
        /// Mirrors the production race deterministically: the GetState
        /// handler publishes further events BEFORE answering, so the
        /// snapshot is always newer than the gap event that triggered it.
        struct RacyStateHandler {
            bus: EventBus,
            seq: AtomicU64,
        }

        impl protonwire_ipc::RequestHandler for RacyStateHandler {
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
                    Request::GetState => {
                        // Events 3 and 4 land WHILE the snapshot request is
                        // being served; the daemon state (stamped 4) already
                        // includes them.
                        for seq in [3u64, 4] {
                            self.seq.store(seq, Ordering::SeqCst);
                            self.bus.publish(ServerMessage::Event(EventEnvelope {
                                seq,
                                event: Event::Notice {
                                    level: NoticeLevel::Info,
                                    message: format!("event {seq}"),
                                },
                            }));
                        }
                        Ok(RequestResult::State {
                            state: DaemonState {
                                protocol_version: PROTOCOL_VERSION,
                                daemon_version: "test-daemon".into(),
                                vpn_state: VpnState::Disconnected,
                                network_integration: NetworkIntegration::Auto,
                                active_owner_uid: None,
                                latest_event_seq: Some(self.seq.load(Ordering::SeqCst)),
                            },
                        })
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

        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(RacyStateHandler {
            bus: EventBus::new(),
            seq: AtomicU64::new(0),
        });
        let server = protonwire_ipc::test_util::TestServer::start(
            dir.path(),
            "racy.sock",
            Arc::clone(&handler),
        )
        .expect("test server binds");
        let path = server.socket_path().to_owned();
        let mut client = dev_client(&path);
        // Handshake reports seq 0, so the client expects event 1 next.

        // Event 1 is lost; event 2 arrives first and triggers the resync.
        handler.seq.store(2, Ordering::SeqCst);
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: 2,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "gap event".into(),
            },
        }));

        match client.next_event().unwrap() {
            ClientEvent::Resynchronized { resumed_at_seq, .. } => assert_eq!(
                resumed_at_seq, 4,
                "the cursor must advance to the snapshot's stamped sequence, \
                 not the gap event's 2"
            ),
            ClientEvent::Event(envelope) => {
                panic!("expected resync, got event {:?}", envelope.event)
            }
        }

        // Events 3 and 4 (already reflected in the snapshot) must never be
        // delivered after it; the next delivery is the first event BEYOND
        // the snapshot.
        handler.seq.store(5, Ordering::SeqCst);
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: 5,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "after snapshot".into(),
            },
        }));
        match client.next_event().unwrap() {
            ClientEvent::Event(envelope) => assert_eq!(
                envelope.seq, 5,
                "snapshot-covered events 3/4 must be suppressed, not replayed"
            ),
            ClientEvent::Resynchronized { .. } => panic!("unexpected second resync"),
        }
    }

    /// QA mutation gap (item G1): daemons that predate the snapshot stamp
    /// (or any None-stamping daemon) must still resynchronize through the
    /// gap-event fallback — `latest_event_seq.unwrap_or(envelope.seq)`.
    /// The mutation `unwrap_or(u64::MAX)` passed the whole suite because
    /// no test exercised the None branch end-to-end; the cursor would
    /// have jumped to MAX and swallowed every subsequent event as stale.
    #[test]
    fn legacy_daemon_without_a_stamp_resyncs_via_the_gap_event() {
        /// Mirrors a pre-stamp daemon: the snapshot carries no sequence.
        struct LegacyStateHandler {
            bus: EventBus,
        }
        impl protonwire_ipc::RequestHandler for LegacyStateHandler {
            fn daemon_version(&self) -> &str {
                "legacy-daemon"
            }
            fn latest_event_seq(&self) -> u64 {
                0
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
                            daemon_version: "legacy-daemon".into(),
                            vpn_state: VpnState::Disconnected,
                            network_integration: NetworkIntegration::Auto,
                            active_owner_uid: None,
                            // The legacy wire shape: no stamp on the wire.
                            latest_event_seq: None,
                        },
                    }),
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

        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(LegacyStateHandler {
            bus: EventBus::new(),
        });
        let server = protonwire_ipc::test_util::TestServer::start(
            dir.path(),
            "legacy.sock",
            Arc::clone(&handler),
        )
        .expect("test server binds");
        let path = server.socket_path().to_owned();
        let mut client = dev_client(&path);
        // Handshake reports seq 0, so the client expects event 1 next.

        // Event 1 is lost; event 2 arrives first and triggers the resync
        // against an unstamped snapshot.
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: 2,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "gap on a legacy daemon".into(),
            },
        }));
        match client.next_event().unwrap() {
            ClientEvent::Resynchronized {
                state,
                resumed_at_seq,
            } => {
                // The fallback cursor is the gap event's own sequence —
                // not u64::MAX, not the handshake's 0.
                assert_eq!(
                    resumed_at_seq, 2,
                    "an unstamped snapshot must fall back to the gap event"
                );
                assert_eq!(state.latest_event_seq, None);
                assert_eq!(state.daemon_version, "legacy-daemon");
            }
            ClientEvent::Event(envelope) => {
                panic!("expected resync, got event {:?}", envelope.event)
            }
        }

        // The cursor landed on 2, so event 3 flows normally afterwards —
        // a MAX cursor would have swallowed it as stale forever.
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: 3,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "after legacy resync".into(),
            },
        }));
        match client.next_event().unwrap() {
            ClientEvent::Event(envelope) => assert_eq!(envelope.seq, 3),
            ClientEvent::Resynchronized { .. } => panic!("unexpected second resync"),
        }
    }

    /// QA mutation gap (item G4): when the snapshot's stamp LAGS the gap
    /// event (a daemon that stamped before later events were published),
    /// the cursor must take the max of the two — dropping the `.max()`
    /// passed the suite because every existing fixture stamped at or
    /// above the gap event. Here the daemon stamps 2 while the gap event
    /// is 4 and a covered event 3 lands mid-request: the cursor must be
    /// 4, and event 3 must never replay after the snapshot.
    #[test]
    fn resync_cursor_takes_the_max_when_the_stamp_lags_the_gap() {
        /// Publishes event 3 while serving GetState, then answers with a
        /// stale stamp of 2 — a snapshot that lags what it was racing.
        struct LaggingStampHandler {
            bus: EventBus,
        }
        impl protonwire_ipc::RequestHandler for LaggingStampHandler {
            fn daemon_version(&self) -> &str {
                "lagging-daemon"
            }
            fn latest_event_seq(&self) -> u64 {
                0
            }
            fn handle(
                &self,
                _ctx: &protonwire_ipc::SessionContext,
                request: Request,
            ) -> Result<RequestResult, RpcError> {
                match request {
                    Request::Ping { nonce } => Ok(RequestResult::Pong { nonce }),
                    Request::GetState => {
                        self.bus.publish(ServerMessage::Event(EventEnvelope {
                            seq: 3,
                            event: Event::Notice {
                                level: NoticeLevel::Info,
                                message: "buffered mid-request".into(),
                            },
                        }));
                        Ok(RequestResult::State {
                            state: DaemonState {
                                protocol_version: PROTOCOL_VERSION,
                                daemon_version: "lagging-daemon".into(),
                                vpn_state: VpnState::Disconnected,
                                network_integration: NetworkIntegration::Auto,
                                active_owner_uid: None,
                                latest_event_seq: Some(2),
                            },
                        })
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

        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(LaggingStampHandler {
            bus: EventBus::new(),
        });
        let server = protonwire_ipc::test_util::TestServer::start(
            dir.path(),
            "lagging.sock",
            Arc::clone(&handler),
        )
        .expect("test server binds");
        let path = server.socket_path().to_owned();
        let mut client = dev_client(&path);
        // Handshake reports seq 0, so the client expects event 1 next.

        // Events 1-3 are lost; event 4 arrives first and triggers the
        // resync, during which event 3 is published and buffered while the
        // snapshot comes back stamped 2.
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: 4,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "gap event".into(),
            },
        }));
        match client.next_event().unwrap() {
            ClientEvent::Resynchronized { resumed_at_seq, .. } => assert_eq!(
                resumed_at_seq, 4,
                "the cursor must take max(stamp 2, gap 4) — a stamp-only \
                 cursor would rewind below the gap event the client saw"
            ),
            ClientEvent::Event(envelope) => {
                panic!("expected resync, got event {:?}", envelope.event)
            }
        }

        // Buffered event 3 (below the cursor) must never replay; the next
        // delivery is the first event BEYOND the cursor.
        handler.bus.publish(ServerMessage::Event(EventEnvelope {
            seq: 5,
            event: Event::Notice {
                level: NoticeLevel::Info,
                message: "after the lagging stamp".into(),
            },
        }));
        match client.next_event().unwrap() {
            ClientEvent::Event(envelope) => assert_eq!(
                envelope.seq, 5,
                "a covered event replayed after the snapshot — the cursor \
                 fell back to the lagging stamp"
            ),
            ClientEvent::Resynchronized { .. } => panic!("unexpected second resync"),
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
            // M2 S2 additions: PRD 9.8 has no dedicated slots for the
            // auth/refresh failure modes, so they map to the general
            // error until the S9 client surface assigns any it owns;
            // persistence-unhealthy IS the credential-backend slot.
            (C::UpstreamCapabilityBlocked, 1),
            (C::UnsupportedChallenge, 1),
            (C::ConfirmationRequired, 1),
            (C::RateLimited, 1),
            (C::CredentialPersistenceUnhealthy, 16),
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

#[cfg(test)]
mod socket_resolution_tests {
    use super::*;

    /// Codex PR review finding 6 (P2): an explicit --socket must WIN over
    /// PROTONWIRE_SOCKET. The pre-fix branch resolved the environment first,
    /// so `daemon stop --socket /run/protonwire-test.sock` with the env set
    /// acted on a different daemon than the one named on the command line —
    /// contradicting the CLI help, where the env is only part of the default.
    /// Pure fn (env passed in) because edition 2024 makes set_var unsafe and
    /// the workspace denies unsafe_code — same seam pattern as checks_for.
    #[test]
    fn explicit_socket_beats_environment_beats_default() {
        assert_eq!(
            resolve_socket_path(Some(Path::new("/run/explicit.sock")), Some("/run/env.sock")),
            PathBuf::from("/run/explicit.sock")
        );
        assert_eq!(
            resolve_socket_path(None, Some("/run/env.sock")),
            PathBuf::from("/run/env.sock")
        );
        assert_eq!(
            resolve_socket_path(Some(Path::new("/run/explicit.sock")), None),
            PathBuf::from("/run/explicit.sock")
        );
        assert_eq!(
            resolve_socket_path(None, None),
            PathBuf::from(DEFAULT_SOCKET_PATH)
        );
    }
}
