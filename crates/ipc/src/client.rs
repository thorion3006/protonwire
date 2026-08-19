//! Client-side IPC transport.
//!
//! Performs the trust checks a client must apply before speaking to the
//! daemon (PRD 6.3): the socket and its parent directory must be owned by
//! root and the directory must not be writable by group/others, so an
//! unprivileged user cannot plant a lookalike socket.

use std::collections::VecDeque;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use protonwire_frontend_api::{
    ClientInfo, ClientMessage, EventEnvelope, HelloAck, PROTOCOL_VERSION, Request, RequestResult,
    Response, RpcError, ServerMessage,
};
use tracing::warn;

use crate::frame::{FrameError, FrameReader, write_msg, write_msg_within};
use crate::peer::PeerCredentials;

/// Default request timeout.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on events buffered mid-request, when `request()` reads events it
/// cannot yet deliver (pr-champion round 6, WO-W3). Mirrors the
/// daemon-side rationale of `crate::bus::SESSION_QUEUE_LEN` (256): a
/// lagging consumer resynchronizes from the sequence gap rather than
/// buffering without bound (PRD FR-127D), so the client holds the same
/// number for the same reason. Overflow drops the OLDEST buffered event
/// and bumps a counter `next_event` surfaces; the induced seq gap is what
/// the latest_event_seq resync machinery exists to recover from — the
/// counter is observability, not correctness.
const PENDING_EVENTS_CAP: usize = 256;

/// Socket-level read poll while a whole frame is pending — deliberately
/// shorter than the logical deadline (the client timeout), mirroring the
/// server's READ_POLL: a mid-frame stall expires the SOCKET read but is
/// retried (resuming the partial frame from the reader's state) until the
/// deadline itself passes. Bounded waits therefore overshoot by at most
/// one poll interval.
const READ_POLL: Duration = Duration::from_millis(250);

/// Failures while establishing a client connection.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// The daemon is not reachable at the configured socket path.
    #[error("daemon unavailable at {path}: {source}")]
    Unreachable {
        /// The socket path that was attempted.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },
    /// The socket failed the client-side trust checks.
    #[error("untrusted socket at {path}: {reason}")]
    Untrusted {
        /// The socket path that was attempted.
        path: PathBuf,
        /// Why the checks failed.
        reason: String,
    },
    /// The daemon refused the hello handshake.
    #[error("daemon refused the handshake: {reason} (supports protocol {supported_version})")]
    HandshakeRefused {
        /// The daemon's highest supported protocol version.
        supported_version: u32,
        /// Machine-readable refusal reason.
        reason: String,
    },
    /// The wire protocol was violated during the handshake.
    #[error("protocol error during handshake: {0}")]
    Protocol(String),
}

/// Client-side socket trust checks.
#[derive(Debug, Clone, Copy)]
pub struct SecurityChecks {
    /// Require the socket and its parent directory to be root-owned with a
    /// non-world-writable directory. Required for production use; tests and
    /// development sockets disable it explicitly.
    pub require_root_socket: bool,
}

impl SecurityChecks {
    /// Production checks.
    pub fn strict() -> Self {
        Self {
            require_root_socket: true,
        }
    }

    /// Development/test checks (for sockets in temporary or per-user
    /// directories). Must never be reachable from release defaults.
    pub fn dev_unchecked() -> Self {
        Self {
            require_root_socket: false,
        }
    }
}

impl Default for SecurityChecks {
    fn default() -> Self {
        Self::strict()
    }
}

/// Errors from a request: structured RPC refusals versus transport
/// failures. A [`RequestError::Transport`] poisons the connection — any
/// stranded bytes desynchronize the stream — so the caller must
/// re-establish the session (rust-review findings 4+5).
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// The daemon answered with a structured refusal.
    #[error(transparent)]
    Rpc(#[from] RpcError),
    /// The connection is broken, timed out, or desynchronized; the
    /// session is unusable and must be re-established.
    #[error("transport failure: {0}")]
    Transport(String),
}

/// A connected, handshaken client transport.
///
/// Events that arrive while waiting for a response are buffered and returned
/// by [`IpcClient::next_event`].
pub struct IpcClient {
    stream: UnixStream,
    /// Stateful frame reader over a duplicate of the session socket, so
    /// reads that expire mid-frame keep their partial progress (a retry
    /// resumes the SAME frame instead of misparsing the remainder as a
    /// fresh length prefix). Socket options are shared with `stream` —
    /// `SO_RCVTIMEO`/`SO_SNDTIMEO` set on one fd govern the socket.
    reader: FrameReader<UnixStream>,
    next_id: u64,
    /// Events read mid-request, awaiting `next_event`. Bounded at
    /// [`PENDING_EVENTS_CAP`]; overflow drops the oldest entry and bumps
    /// `dropped_events`.
    pending_events: VecDeque<EventEnvelope>,
    /// Events dropped after the pending queue hit [`PENDING_EVENTS_CAP`]
    /// (cumulative). Observability only: the drop-induced seq gap is
    /// recovered by the latest_event_seq resync path.
    dropped_events: u64,
    /// Portion of `dropped_events` not yet surfaced by `next_event`'s log.
    unreported_drops: u64,
    timeout: Duration,
    poisoned: bool,
    ack: HelloAck,
}

impl IpcClient {
    /// Connects, verifies trust, and performs the hello handshake.
    pub fn connect(
        path: &Path,
        client: &ClientInfo,
        checks: SecurityChecks,
    ) -> Result<Self, ConnectError> {
        Self::connect_with_timeout(path, client, checks, DEFAULT_REQUEST_TIMEOUT)
    }

    /// [`IpcClient::connect`] with an explicit handshake/request timeout
    /// (tests use short values).
    pub fn connect_with_timeout(
        path: &Path,
        client: &ClientInfo,
        checks: SecurityChecks,
        timeout: Duration,
    ) -> Result<Self, ConnectError> {
        if checks.require_root_socket {
            // Defense in depth: the filesystem checks race the connect, so
            // the authoritative check is the kernel-captured SO_PEERCRED of
            // the *connected* stream — the daemon peer must be root.
            verify_socket_trusted(path)?;
        }
        let stream = UnixStream::connect(path).map_err(|source| ConnectError::Unreachable {
            path: path.to_owned(),
            source,
        })?;
        if checks.require_root_socket {
            let peer = PeerCredentials::of(&stream).map_err(|e| ConnectError::Untrusted {
                path: path.to_owned(),
                reason: format!("peer credentials unavailable: {e}"),
            })?;
            if !peer.is_root() {
                return Err(ConnectError::Untrusted {
                    path: path.to_owned(),
                    reason: format!("daemon peer UID {} is not root", peer.uid),
                });
            }
        }
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|source| ConnectError::Unreachable {
                path: path.to_owned(),
                source,
            })?;
        // The write ceiling matches: a daemon that stops reading mid-request
        // cannot pin the client's writes either (Codex PR review round 2,
        // finding 7).
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|source| ConnectError::Unreachable {
                path: path.to_owned(),
                source,
            })?;
        // The frame reader gets its own descriptor of the same socket.
        let read_half = stream
            .try_clone()
            .map_err(|source| ConnectError::Unreachable {
                path: path.to_owned(),
                source,
            })?;
        let mut transport = Self {
            stream,
            reader: FrameReader::new(read_half),
            next_id: 0,
            pending_events: VecDeque::new(),
            dropped_events: 0,
            unreported_drops: 0,
            timeout,
            poisoned: false,
            ack: HelloAck {
                protocol_version: PROTOCOL_VERSION,
                daemon_version: String::new(),
                latest_event_seq: 0,
            },
        };
        let ack = transport.handshake(client.clone())?;
        transport.ack = ack;
        Ok(transport)
    }

    /// The daemon's hello acknowledgement.
    pub fn hello(&self) -> &HelloAck {
        &self.ack
    }

    /// Overrides the per-request timeout (tests use short values). Also
    /// bounds a whole request: a stream of events cannot keep one alive
    /// past the deadline, and a peer that stops reading cannot pin the
    /// request's write either.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
        let _ = self.stream.set_read_timeout(Some(timeout));
        let _ = self.stream.set_write_timeout(Some(timeout));
    }

    /// Reads the handshake reply bounded by the connect timeout as a WHOLE
    /// (consolidated round 3, item B): a daemon dribbling the reply one
    /// byte per sub-timeout interval keeps every socket read succeeding,
    /// so only a codec-level deadline ends the wait. The socket polls at
    /// [`READ_POLL`] inside that deadline so a mid-frame stall resumes
    /// from the partial state instead of discarding it.
    fn handshake(&mut self, client: ClientInfo) -> Result<HelloAck, ConnectError> {
        write_msg(
            &mut self.stream,
            &ClientMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
                client,
            },
        )
        .map_err(|e| ConnectError::Protocol(e.to_string()))?;
        let deadline = Instant::now() + self.timeout;
        let _ = self
            .stream
            .set_read_timeout(Some(READ_POLL.min(self.timeout)));
        let message = loop {
            match self.reader.read_msg_within::<ServerMessage>(deadline) {
                Ok(message) => break message,
                Err(FrameError::Io(e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if Instant::now() >= deadline {
                        return Err(ConnectError::Protocol(
                            "handshake timed out waiting for the daemon".into(),
                        ));
                    }
                    continue; // partial frame retained; retry the poll
                }
                Err(e) => return Err(ConnectError::Protocol(e.to_string())),
            }
        };
        let _ = self.stream.set_read_timeout(Some(self.timeout));
        match message {
            ServerMessage::HelloAck(ack) if ack.protocol_version <= PROTOCOL_VERSION => Ok(ack),
            ServerMessage::HelloError(err) => Err(ConnectError::HandshakeRefused {
                supported_version: err.supported_version,
                reason: err.reason,
            }),
            other => Err(ConnectError::Protocol(format!(
                "unexpected message during handshake: {other:?}"
            ))),
        }
    }

    /// Sends a request and blocks for its correlated response.
    ///
    /// Any read/write failure, timeout, or protocol desynchronization
    /// returns [`RequestError::Transport`] and poisons the connection:
    /// the stream may hold stranded bytes, so every later call fails fast
    /// until the caller reconnects.
    pub fn request(&mut self, request: Request) -> Result<RequestResult, RequestError> {
        if self.poisoned {
            return Err(RequestError::Transport(
                "connection unusable after a previous failure; reconnect".into(),
            ));
        }
        let deadline = std::time::Instant::now() + self.timeout;
        let id = self.next_id;
        self.next_id += 1;
        // Codex PR review round 2, finding 7: the write side gets the same
        // deadline treatment the reads got in round 1. A handshaken peer
        // that stops reading pins write_all once the socket buffers fill
        // (frames may be nearly MAX_FRAME_LEN), which would otherwise
        // block past the whole-request guarantee set_timeout documents.
        // R7-1 closes the residual write gap the same way the server's
        // writer threads got: the request write is codec-bounded by the
        // whole-request deadline (write_msg_within — poll-for-writability
        // inside the remaining budget), because SO_SNDTIMEO cannot bound a
        // MESSAGE, for the two measured reasons in frame.rs's write-side
        // record: it bounds each WAIT, not the message (progress resets
        // it; a multi-syscall write multiplies it), and under steady
        // drain it never expires at all — every dribbled byte that frees
        // space starts a fresh wait (sec round-7 probe; review-log track
        // item). The socket-wide SO_SNDTIMEO that
        // connect/set_timeout applied stays as a syscall-level backstop,
        // and the zero-budget guard remains load-bearing: a spent deadline
        // must not enter the write path at all.
        let write_budget = deadline.saturating_duration_since(std::time::Instant::now());
        if write_budget.is_zero() {
            self.poisoned = true;
            return Err(RequestError::Transport(
                "request timed out without a response".into(),
            ));
        }
        write_msg_within(
            &mut self.stream,
            &ClientMessage::Request { id, request },
            deadline,
        )
        .map_err(|e| {
            self.poisoned = true;
            RequestError::Transport(format!("write failed: {e}"))
        })?;
        loop {
            let now = std::time::Instant::now();
            if now > deadline {
                self.poisoned = true;
                return Err(RequestError::Transport(
                    "request timed out without a response".into(),
                ));
            }
            // Bound THIS read by the remaining budget (Codex PR review
            // finding 9): the socket timeout is the full self.timeout, so
            // an event arriving near the deadline would otherwise let the
            // next read block a whole extra timeout past it. A zero
            // remainder is the deadline itself (a zero SO_RCVTIMEO means
            // "block forever" on Linux, so it must not reach the socket).
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                self.poisoned = true;
                return Err(RequestError::Transport(
                    "request timed out without a response".into(),
                ));
            }
            if let Err(e) = self.stream.set_read_timeout(Some(remaining)) {
                self.poisoned = true;
                return Err(RequestError::Transport(format!(
                    "cannot apply request deadline: {e}"
                )));
            }
            // Codec-level deadline (final review pass): the socket timeout
            // above bounds one SYSCALL, so a daemon dribbling the response
            // one byte per sub-timeout keeps every read succeeding and
            // would stretch the frame past the whole-request deadline —
            // the same gap round 3 closed for handshake/next_event. The
            // deadline-aware read fails mid-frame, and the Err arm below
            // classifies a post-deadline TimedOut as the request timeout.
            let outcome = self.reader.read_msg_within::<ServerMessage>(deadline);
            // Restore the whole-request timeout for callers between loops
            // (next_event reads with it once request returns).
            let _ = self.stream.set_read_timeout(Some(self.timeout));
            match outcome {
                Ok(ServerMessage::Response(response)) => match response {
                    Response::Ok { id: seen, result } if seen == id => return Ok(result),
                    Response::Error { id: seen, error } if seen == id => return Err(error.into()),
                    other => {
                        self.poisoned = true;
                        return Err(RequestError::Transport(format!(
                            "out-of-order response id {}",
                            other.id()
                        )));
                    }
                },
                Ok(ServerMessage::Event(envelope)) => {
                    // Bound the buffer like the daemon bounds its session
                    // queues (bus::SESSION_QUEUE_LEN's rationale): drop the
                    // OLDEST entry and account it — the seq gap it induces
                    // is exactly what the latest_event_seq resync path
                    // recovers from, while the counter keeps it observable.
                    if self.pending_events.len() >= PENDING_EVENTS_CAP {
                        self.pending_events.pop_front();
                        self.dropped_events += 1;
                        self.unreported_drops += 1;
                    }
                    self.pending_events.push_back(envelope);
                }
                Ok(other) => {
                    self.poisoned = true;
                    return Err(RequestError::Transport(format!(
                        "unexpected message mid-request: {other:?}"
                    )));
                }
                Err(e) => {
                    self.poisoned = true;
                    let message = if std::time::Instant::now() >= deadline {
                        // The deadline-bounded read expired: report it as
                        // the request timeout it is, not a generic I/O
                        // failure.
                        "request timed out without a response".to_owned()
                    } else {
                        format!("read failed: {e}")
                    };
                    return Err(RequestError::Transport(message));
                }
            }
        }
    }

    /// Returns the next buffered or socket event, blocking until one arrives
    /// or the client timeout elapses — whichever comes first.
    ///
    /// Deadline policy (consolidated round 3, item B): the wait is bounded
    /// by [`IpcClient::set_timeout`]'s value, because a daemon dribbling
    /// bytes faster than the per-syscall socket timeout would otherwise pin
    /// the caller forever. Expiry surfaces as [`io::ErrorKind::TimedOut`]
    /// meaning "no event yet": callers re-poll rather than reconnect (an
    /// idle-but-healthy daemon between events is the normal case). A frame
    /// that stalls mid-read keeps its partial state, so the next call
    /// resumes the SAME frame instead of desynchronizing.
    ///
    /// Fails fast on a poisoned transport (Codex PR review finding 10),
    /// exactly like [`IpcClient::request`]: after a timeout, I/O failure,
    /// or desynchronization the stream may hold stranded bytes, so an
    /// event-loop caller must get its reconnect instruction immediately
    /// instead of blocking for the socket timeout or consuming a stranded
    /// late response.
    pub fn next_event(&mut self) -> io::Result<EventEnvelope> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection unusable after a previous failure; reconnect",
            ));
        }
        self.surface_pending_drops();
        if let Some(envelope) = self.pending_events.pop_front() {
            return Ok(envelope);
        }
        let deadline = Instant::now() + self.timeout;
        let _ = self
            .stream
            .set_read_timeout(Some(READ_POLL.min(self.timeout)));
        let outcome = loop {
            match self.reader.read_msg_within::<ServerMessage>(deadline) {
                Ok(message) => break Ok(message),
                Err(FrameError::Io(e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if Instant::now() >= deadline {
                        break Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("no event within {:?}", self.timeout),
                        ));
                    }
                    continue; // partial frame retained; retry the poll
                }
                Err(e) => break Err(map_frame_error(e)),
            }
        };
        let _ = self.stream.set_read_timeout(Some(self.timeout));
        match outcome {
            Ok(ServerMessage::Event(envelope)) => Ok(envelope),
            Ok(other) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected message while awaiting event: {other:?}"),
            )),
            Err(e) => Err(e),
        }
    }

    /// Drops buffered events at or below `seq`. Called after a resync whose
    /// snapshot already reflects them (Codex PR review round 2, finding 1):
    /// events that arrived while the `GetState` request was in flight would
    /// otherwise be delivered AFTER the newer snapshot and regress the
    /// client's state view.
    pub fn discard_events_through(&mut self, seq: u64) {
        self.pending_events.retain(|envelope| envelope.seq > seq);
    }

    /// Events dropped from the pending queue after it hit
    /// PENDING_EVENTS_CAP (cumulative across the connection's life).
    /// Observability only: after a drop-induced seq gap, correctness is
    /// recovered by resynchronizing from `latest_event_seq`, not by this
    /// count.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Surfaces queue-overflow drops on the first `next_event` after they
    /// happened (one log per overflow episode, with the running total) —
    /// the drop itself happens silently inside `request()`, where there is
    /// no caller to report to.
    fn surface_pending_drops(&mut self) {
        if self.unreported_drops > 0 {
            warn!(
                dropped = self.unreported_drops,
                total = self.dropped_events,
                cap = PENDING_EVENTS_CAP,
                "pending event queue overflowed while a request was in flight; \
                 the oldest events were dropped — the seq gap is recovered by \
                 the latest_event_seq resync"
            );
            self.unreported_drops = 0;
        }
    }
}

fn map_frame_error(e: crate::frame::FrameError) -> io::Error {
    match e {
        crate::frame::FrameError::Io(io) => io,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

/// Verifies the daemon socket is trustworthy before connecting: strict
/// walk of every path component from the socket leaf to `/` — no
/// symlinks, the leaf a socket without world write, every ancestor a
/// root-owned directory without group/world write (the M2 S12
/// consolidation onto the `fs_trust` walker's semantics; see
/// [`crate::peer`] for the walk rule and the disclosed duplication
/// decision).
///
/// A missing socket (the leaf's `lstat` answering NotFound) reports
/// [`ConnectError::Unreachable`] — "daemon not there" — while every
/// other inspection failure is an [`ConnectError::Untrusted`] naming the
/// offending component and defect.
pub fn verify_socket_trusted(path: &Path) -> Result<(), ConnectError> {
    match crate::peer::walk_socket_trust(path, Path::new("/")) {
        Ok(()) => Ok(()),
        Err(crate::peer::SocketTrustError::Io {
            path: inspected,
            source,
        }) if inspected == path && source.kind() == io::ErrorKind::NotFound => {
            Err(ConnectError::Unreachable {
                path: path.to_owned(),
                source,
            })
        }
        Err(e) => Err(ConnectError::Untrusted {
            path: path.to_owned(),
            reason: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use protonwire_frontend_api::{RpcErrorCode, VpnState};

    use crate::EventBus;

    struct EchoHandler {
        version: String,
        bus: EventBus,
        seq: AtomicU64,
    }

    impl crate::server::RequestHandler for EchoHandler {
        fn daemon_version(&self) -> &str {
            &self.version
        }
        fn latest_event_seq(&self) -> u64 {
            self.seq.load(Ordering::SeqCst)
        }
        fn handle(
            &self,
            _ctx: &crate::server::SessionContext,
            request: Request,
        ) -> Result<RequestResult, RpcError> {
            match request {
                Request::Ping { nonce } => Ok(RequestResult::Pong { nonce }),
                Request::Shutdown => Err(RpcError::new(
                    RpcErrorCode::PermissionDenied,
                    "admin required",
                )),
                Request::GetState => Ok(RequestResult::State {
                    state: protonwire_frontend_api::DaemonState {
                        protocol_version: PROTOCOL_VERSION,
                        daemon_version: self.version.clone(),
                        vpn_state: VpnState::Disconnected,
                        network_integration: protonwire_frontend_api::NetworkIntegration::Auto,
                        active_owner_uid: None,
                        latest_event_seq: Some(self.seq.load(Ordering::SeqCst)),
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

    fn test_client_info() -> ClientInfo {
        ClientInfo {
            name: "ipc-test".into(),
            version: "0".into(),
            surface: protonwire_frontend_api::ClientSurface::Other,
        }
    }

    fn spawn_server(dir: &tempfile::TempDir) -> crate::test_util::TestServer {
        let handler = Arc::new(EchoHandler {
            version: "test-daemon".into(),
            bus: EventBus::new(),
            seq: AtomicU64::new(0),
        });
        crate::test_util::TestServer::start(dir.path(), "test.sock", handler).unwrap()
    }

    #[test]
    fn handshake_ping_and_state_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let server = spawn_server(&dir);
        let path = server.socket_path().to_owned();
        let mut client =
            IpcClient::connect(&path, &test_client_info(), SecurityChecks::dev_unchecked())
                .unwrap();
        assert_eq!(client.hello().daemon_version, "test-daemon");
        match client
            .request(Request::Ping { nonce: "n1".into() })
            .unwrap()
        {
            RequestResult::Pong { nonce } => assert_eq!(nonce, "n1"),
            other => panic!("unexpected result: {other:?}"),
        }
        assert!(matches!(
            client.request(Request::GetState).unwrap(),
            RequestResult::State { .. }
        ));
    }

    #[test]
    fn error_response_preserves_code() {
        let dir = tempfile::tempdir().unwrap();
        let server = spawn_server(&dir);
        let path = server.socket_path().to_owned();
        let mut client =
            IpcClient::connect(&path, &test_client_info(), SecurityChecks::dev_unchecked())
                .unwrap();
        match client.request(Request::Shutdown).unwrap_err() {
            RequestError::Rpc(rpc) => {
                assert_eq!(
                    rpc.code,
                    protonwire_frontend_api::RpcErrorCode::PermissionDenied
                );
            }
            other => panic!("expected an RPC refusal, got {other:?}"),
        }
    }

    /// Recorded decision #1 (2026-08-17, docs/m2-plan.md): the SDK's
    /// request path emits the FLAT wire shape — `data: {id, method,
    /// params}`. A scripted daemon reads the RAW frame bytes and inspects
    /// the JSON itself, pinning what the typed round-trip never shows:
    /// no `request` wrapper object may reappear on the wire.
    #[test]
    fn request_path_emits_the_flat_wire_shape() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flat-wire.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel::<serde_json::Value>();
        std::thread::spawn(move || {
            let Ok((mut peer, _)) = listener.accept() else {
                return;
            };
            let _ = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
            let _ = crate::frame::write_msg(
                &mut peer,
                &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                    protocol_version: 1,
                    daemon_version: "flat".into(),
                    latest_event_seq: 0,
                }),
            );
            // The raw frame the SDK's request path actually sent, parsed
            // and reported so the test asserts on the peer's view.
            let raw = match crate::frame::read_frame(&mut peer) {
                Ok(raw) => raw,
                Err(e) => panic!("request frame never arrived: {e}"),
            };
            let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            let _ = seen_tx.send(json);
            let _ = crate::frame::write_msg(
                &mut peer,
                &ServerMessage::Response(Response::Ok {
                    id: 0,
                    result: RequestResult::Pong { nonce: "p".into() },
                }),
            );
            std::thread::sleep(Duration::from_secs(30));
        });

        let mut client = IpcClient::connect_with_timeout(
            &path,
            &test_client_info(),
            SecurityChecks::dev_unchecked(),
            Duration::from_secs(2),
        )
        .unwrap();
        client
            .request(Request::Ping { nonce: "p".into() })
            .expect("the scripted peer answers");

        let json = seen_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the peer reports the observed frame");
        // Full-object JSON equality — `Value` equality is
        // order-insensitive, the right equivalence for a frame: the
        // observed bytes must be EXACTLY the flat shape, so no
        // `request` wrapper, no extra key, and no missing one can ride
        // the wire unasserted.
        assert_eq!(
            json,
            serde_json::json!({
                "type": "request",
                "data": {
                    "id": 0,
                    "method": "ping",
                    "params": { "nonce": "p" }
                }
            }),
            "the SDK's request frame must be exactly the flat shape"
        );
    }

    #[test]
    fn untrusted_socket_rejected_when_checks_strict() {
        let dir = tempfile::tempdir().unwrap();
        let server = spawn_server(&dir);
        let path = server.socket_path().to_owned();
        let err = IpcClient::connect(&path, &test_client_info(), SecurityChecks::strict())
            .err()
            .expect("strict checks must reject a non-root socket");
        match err {
            ConnectError::Untrusted { reason, .. } => {
                assert!(reason.contains("root") || reason.contains("writable"));
            }
            other => panic!("expected Untrusted, got {other:?}"),
        }
    }

    /// S12 item 1 (the walker consolidation): the trust check used
    /// `metadata`, which FOLLOWS links — a symlink standing where the
    /// daemon's socket should be was judged by whatever it pointed at, so
    /// a lookalike link in a root-owned directory laundered the socket
    /// leaf (and every ancestor above the parent went uninspected). The
    /// consolidated check walks every component with `lstat`-style
    /// inspection and NAMES the defect: a symlinked socket path must be
    /// rejected as a symlink. Pre-fix red (unprivileged): the follow
    /// reached the target socket, tripped only the owner-UID check, and
    /// the reason read "socket owner UID ... is not root" — no
    /// "symbolic link" anywhere.
    #[test]
    fn strict_checks_name_a_symlinked_socket_path() {
        let dir = tempfile::tempdir().unwrap();
        // A real (stale) socket for the link to resolve to, so the
        // type check alone cannot reject it.
        let target = dir.path().join("real.sock");
        drop(std::os::unix::net::UnixListener::bind(&target).unwrap());
        let via = dir.path().join("daemon.sock");
        std::os::unix::fs::symlink(&target, &via).unwrap();

        let err = verify_socket_trusted(&via)
            .expect_err("a symlink at the socket path must never be trusted");
        match err {
            ConnectError::Untrusted { path, reason } => {
                assert_eq!(path, via, "the refusal must name the link's path");
                assert!(
                    reason.contains("symbolic link"),
                    "the refusal must name the symlink itself, got: {reason}"
                );
            }
            other => panic!("expected Untrusted, got {other:?}"),
        }
    }

    /// S12 item 1: the old check inspected ONE ancestor (the direct
    /// parent). A group/world-writable directory TWO or more levels above
    /// the socket — enough for anyone to plant a lookalike socket in it —
    /// passed unseen. The consolidated walk lstat-checks every ancestor up
    /// to the trust root; the deep defect must be named. Pre-fix red
    /// (unprivileged): the owner-UID check on the socket tripped first and
    /// the reason carried no "writable".
    #[test]
    fn strict_checks_reject_a_writable_ancestor_above_the_parent() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        // The writable grandparent is the planting surface: anyone can
        // create entries in it and shadow the path the deeper components
        // spell out.
        let grandparent = dir.path().join("runtime");
        let parent = grandparent.join("protonwire");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::set_permissions(&grandparent, std::fs::Permissions::from_mode(0o770)).unwrap();
        let socket = parent.join("protonwire.sock");
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        let err = verify_socket_trusted(&socket)
            .expect_err("a group/world-writable ancestor must never be trusted");
        match err {
            ConnectError::Untrusted { reason, .. } => {
                assert!(
                    reason.contains("writable") && reason.contains(grandparent.to_str().unwrap()),
                    "the refusal must name the writable ancestor, got: {reason}"
                );
            }
            other => panic!("expected Untrusted, got {other:?}"),
        }
    }

    /// S12 item 1: the old check never looked at the socket leaf's OWN
    /// mode. A world-writable socket (0o666-ish) is world-CONNECTABLE —
    /// connect(2) needs write permission on the socket inode — and the
    /// leaf's mode is part of the trust surface. Group-write on the leaf
    /// stays allowed (the R9-1 0o660 group hand-off is the production
    /// shape); world-write must be named. Pre-fix red (unprivileged): the
    /// owner-UID check tripped first, no "world" in the reason.
    #[test]
    fn strict_checks_reject_a_world_writable_socket_leaf() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("protonwire.sock");
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();

        let err = verify_socket_trusted(&socket)
            .expect_err("a world-writable socket leaf must never be trusted");
        match err {
            ConnectError::Untrusted { reason, .. } => {
                assert!(
                    reason.contains("world"),
                    "the refusal must name the world-writable leaf, got: {reason}"
                );
            }
            other => panic!("expected Untrusted, got {other:?}"),
        }
    }

    /// A scripted daemon-side peer: handshakes, then answers one request
    /// with an Event after `event_delay` and never responds.
    struct EventThenSilencePeer;

    impl EventThenSilencePeer {
        fn spawn(dir: &tempfile::TempDir, event_delay: std::time::Duration) -> std::path::PathBuf {
            use std::os::unix::net::UnixListener;
            let path = dir.path().join("eventful.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let delay = event_delay;
            std::thread::spawn(move || {
                let Ok((mut peer, _)) = listener.accept() else {
                    return;
                };
                let _ = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
                let _ = crate::frame::write_msg(
                    &mut peer,
                    &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                        protocol_version: 1,
                        daemon_version: "eventful".into(),
                        latest_event_seq: 0,
                    }),
                );
                // Answer the request with an event after the delay, then
                // swallow everything forever.
                let _ = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
                std::thread::sleep(delay);
                let _ = crate::frame::write_msg(
                    &mut peer,
                    &ServerMessage::Event(protonwire_frontend_api::EventEnvelope {
                        seq: 1,
                        event: protonwire_frontend_api::Event::Notice {
                            level: protonwire_frontend_api::NoticeLevel::Info,
                            message: "mid-request".into(),
                        },
                    }),
                );
                while crate::frame::read_msg::<_, ClientMessage>(&mut peer).is_ok() {}
            });
            path
        }
    }

    /// Codex PR review finding 9 (P2): the request loop's per-read timeout
    /// was the full `self.timeout`, so an event arriving shortly before the
    /// deadline made the NEXT read block up to a whole extra timeout — an
    /// event at 9.9 s of a 10 s request could hold the caller to ~19.9 s.
    /// Each read must be bounded by the deadline's remaining duration.
    #[test]
    fn request_deadline_bounds_every_read_not_just_the_first() {
        use std::time::{Duration, Instant};

        let dir = tempfile::tempdir().unwrap();
        let timeout = Duration::from_secs(1);
        let path = EventThenSilencePeer::spawn(&dir, Duration::from_millis(400));
        let mut client = IpcClient::connect_with_timeout(
            &path,
            &test_client_info(),
            SecurityChecks::dev_unchecked(),
            timeout,
        )
        .unwrap();

        let started = Instant::now();
        let err = client
            .request(Request::Ping { nonce: "p".into() })
            .expect_err("silent after one event must time out");
        let elapsed = started.elapsed();
        assert!(
            matches!(err, RequestError::Transport(_)),
            "timeout is a transport failure, got {err:?}"
        );
        // The event at 0.4 s must not buy the (silent) read a full extra
        // second: pre-fix the call returned at ~1.4 s.
        assert!(
            elapsed < timeout + Duration::from_millis(200),
            "request overran its deadline: {elapsed:?} (timeout {timeout:?})"
        );
    }

    /// Codex PR review round 2, finding 7 (P2): round 1 bounded every READ
    /// by the request deadline, but the write side had no timeout at all.
    /// A handshaken peer that stops reading pins `write_all` once the
    /// socket buffers fill — and frames may be nearly MAX_FRAME_LEN — so
    /// `set_timeout`'s whole-request guarantee did not bound the request.
    ///
    /// Consolidated round 3, item D (rust-reviewer + qa-engineer): the
    /// deaf peer's receive buffer is pinned to 4 KiB (std exposes no
    /// UnixStream helper, hence the nix setsockopt) so the ~0.86 MiB
    /// frame blocks regardless of the host's kernel buffer defaults, and
    /// the assertion holds on the Transport-vs-timing contract — the
    /// "write failed" wording is informational.
    #[test]
    fn request_write_is_bounded_by_the_deadline() {
        use std::os::unix::net::UnixListener;
        use std::time::{Duration, Instant};

        // Completes the handshake, then never reads again.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deaf.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let Ok((mut peer, _)) = listener.accept() else {
                return;
            };
            nix::sys::socket::setsockopt(&peer, nix::sys::socket::sockopt::RcvBuf, &4096usize)
                .expect("SO_RCVBUF applies");
            let _ = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
            let _ = crate::frame::write_msg(
                &mut peer,
                &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                    protocol_version: 1,
                    daemon_version: "deaf".into(),
                    latest_event_seq: 0,
                }),
            );
            // Swallow nothing further: the client's send buffers fill and
            // its write blocks.
            std::thread::sleep(Duration::from_secs(30));
        });

        let mut client = IpcClient::connect_with_timeout(
            &path,
            &test_client_info(),
            SecurityChecks::dev_unchecked(),
            Duration::from_millis(300),
        )
        .unwrap();
        let nonce = "x".repeat(900_000); // ~0.86 MiB frame, under MAX_FRAME_LEN
        let started = Instant::now();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            let outcome = client.request(Request::Ping { nonce });
            let _ = done_tx.send(());
            outcome
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
            "request() overran its deadline — the write is unbounded"
        );
        let outcome = worker.join().unwrap();
        match outcome {
            Err(RequestError::Transport(message)) => {
                // Informational only: the load-bearing contract is the
                // Transport kind plus the timing bound below.
                eprintln!("bounded write failure reports: {message}");
            }
            other => panic!("expected a transport failure, got {other:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the failed write must return at the deadline, not hang"
        );
    }

    /// QA mutation gap (item G6): with a deadline already expired at the
    /// write (a sub-microsecond timeout makes `deadline - now` saturate to
    /// zero), the request must refuse to write at all. The observed red
    /// on this kernel is a FAST WRONG RESULT: a sub-µs SO_SNDTIMEO
    /// yields an immediate EAGAIN, so without the guard the 0.86 MiB
    /// frame into the never-reading 4 KiB peer fails at ~0.02 s with a
    /// "write failed" wording that flunks the deadline-refusal assert
    /// below. A HANG is the kernel-dependent possibility — on kernels
    /// that round the zero-duration timeout to blocking ("block forever"
    /// on Linux) the same mutation pins the caller indefinitely — which
    /// is the mode the watchdog assert exists to catch.
    #[test]
    fn request_refuses_to_write_when_the_budget_is_already_zero() {
        use std::os::unix::net::UnixListener;
        use std::time::{Duration, Instant};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero-budget.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let Ok((mut peer, _)) = listener.accept() else {
                return;
            };
            nix::sys::socket::setsockopt(&peer, nix::sys::socket::sockopt::RcvBuf, &4096usize)
                .expect("SO_RCVBUF applies");
            let _ = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
            let _ = crate::frame::write_msg(
                &mut peer,
                &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                    protocol_version: 1,
                    daemon_version: "deaf".into(),
                    latest_event_seq: 0,
                }),
            );
            std::thread::sleep(Duration::from_secs(30));
        });

        let mut client = IpcClient::connect_with_timeout(
            &path,
            &test_client_info(),
            SecurityChecks::dev_unchecked(),
            Duration::from_secs(1),
        )
        .unwrap();
        // A sub-microsecond timeout: the deadline is (all but certainly)
        // in the past by the time the write budget is computed.
        client.set_timeout(Duration::from_nanos(1));
        let started = Instant::now();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            let outcome = client.request(Request::Ping {
                nonce: "x".repeat(900_000),
            });
            let _ = done_tx.send(());
            outcome
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
            "a zero write budget hung the request — the guard is gone"
        );
        match worker.join().unwrap() {
            Err(RequestError::Transport(message)) => {
                assert!(
                    message.contains("timed out"),
                    "expected the deadline refusal, got: {message}"
                );
            }
            other => panic!("expected a transport failure, got {other:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the refusal must be immediate, not a blocked write"
        );
    }

    /// Final review pass (both reviewers): the request loop's read was
    /// plain `read_msg`, bounded only by the per-syscall socket timeout —
    /// the exact gap consolidated round 3 closed for the handshake and
    /// next_event. A daemon dribbling the response frame faster than that
    /// timeout keeps every read succeeding, so `request()` stayed pinned
    /// past its whole-request deadline. The read must be bounded at the
    /// codec level.
    #[test]
    fn request_is_bounded_against_an_ever_dribbling_daemon() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        use std::time::{Duration, Instant};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dribble-response.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let Ok((mut peer, _)) = listener.accept() else {
                return;
            };
            let _ = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
            let _ = crate::frame::write_msg(
                &mut peer,
                &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                    protocol_version: 1,
                    daemon_version: "dribbler".into(),
                    latest_event_seq: 0,
                }),
            );
            // Swallow the request, then announce a plausible frame length
            // and dribble payload bytes forever: no single read ever hits
            // the socket timeout.
            let _ = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
            let announced = 60_000u32.to_be_bytes();
            let _ = peer.write_all(&announced);
            let _ = peer.flush();
            let mut byte = b'x';
            loop {
                if peer.write_all(&[byte]).is_err() {
                    break;
                }
                let _ = peer.flush();
                byte = byte.wrapping_add(1);
                std::thread::sleep(Duration::from_millis(25));
            }
        });

        let mut client = IpcClient::connect_with_timeout(
            &path,
            &test_client_info(),
            SecurityChecks::dev_unchecked(),
            Duration::from_millis(300),
        )
        .unwrap();

        let started = Instant::now();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            let outcome = client.request(Request::Ping { nonce: "p".into() });
            let _ = done_tx.send(());
            outcome
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
            "request() is pinned by a dribbled response frame despite the deadline"
        );
        let err = worker
            .join()
            .unwrap()
            .expect_err("the dribble must expire the request");
        assert!(
            matches!(err, RequestError::Transport(_)),
            "expiry is a transport failure, got {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the expiry must arrive at the request deadline, not after a full frame"
        );
    }

    /// Codex PR review finding 10 (P2): next_event must fail fast once the
    /// transport is poisoned, exactly like request — otherwise a caller
    /// returning to its event loop after a failed request blocks for the
    /// full socket timeout or consumes a stranded late response.
    #[test]
    fn next_event_fails_fast_after_poisoning() {
        use std::time::{Duration, Instant};

        let dir = tempfile::tempdir().unwrap();
        let path = EventThenSilencePeer::spawn(&dir, Duration::from_millis(400));
        let mut client = IpcClient::connect_with_timeout(
            &path,
            &test_client_info(),
            SecurityChecks::dev_unchecked(),
            Duration::from_secs(1),
        )
        .unwrap();

        let err = client
            .request(Request::Ping { nonce: "p".into() })
            .expect_err("silent peer must poison the transport");
        assert!(matches!(err, RequestError::Transport(_)));

        // A long timeout from here on: the fail-fast must NOT depend on the
        // socket timeout. Pre-fix this call blocked for the full 10 s.
        client.set_timeout(Duration::from_secs(10));
        let started = Instant::now();
        let err = client
            .next_event()
            .expect_err("poisoned transport must fail fast in next_event");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "next_event blocked {elapsed:?} on a poisoned transport",
            elapsed = started.elapsed()
        );
        assert!(
            err.to_string().to_lowercase().contains("reconnect"),
            "error should instruct a reconnect, got: {err}"
        );
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionAborted);
    }

    /// A scripted daemon-side peer that trickles the HelloAck one byte per
    /// interval and holds the socket open — the client-side mirror of the
    /// server's hello dribble (consolidated round 3, item B).
    struct DribblingAckPeer;

    impl DribblingAckPeer {
        fn spawn(dir: &tempfile::TempDir, ms_per_byte: u64) -> std::path::PathBuf {
            use std::io::Write;
            use std::os::unix::net::UnixListener;
            let path = dir.path().join("dribble-ack.sock");
            let listener = UnixListener::bind(&path).unwrap();
            std::thread::spawn(move || {
                let Ok((mut peer, _)) = listener.accept() else {
                    return;
                };
                let _ = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
                let mut frame = Vec::new();
                let _ = crate::frame::write_msg(
                    &mut frame,
                    &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                        protocol_version: 1,
                        daemon_version: "dribbler".into(),
                        latest_event_seq: 0,
                    }),
                );
                for byte in frame {
                    if peer.write_all(&[byte]).is_err() {
                        break;
                    }
                    let _ = peer.flush();
                    std::thread::sleep(Duration::from_millis(ms_per_byte));
                }
                // Hold the socket: the dribble must fail on the CLIENT's
                // deadline, not on the daemon hanging up.
                std::thread::sleep(Duration::from_secs(30));
            });
            path
        }
    }

    /// Consolidated round 3, item B (rust-reviewer): the handshake read was
    /// stateless `read_msg` under a socket read timeout — per-syscall. A
    /// daemon trickling the HelloAck faster than the timeout keeps every
    /// read succeeding, so connect() pinned forever DESPITE the timeout.
    /// The handshake must be bounded by the connect timeout as a whole.
    #[test]
    fn handshake_is_bounded_against_a_dribbling_daemon() {
        use std::time::{Duration, Instant};

        let dir = tempfile::tempdir().unwrap();
        let path = DribblingAckPeer::spawn(&dir, 25);
        let started = Instant::now();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let outcome = IpcClient::connect_with_timeout(
                &path,
                &test_client_info(),
                SecurityChecks::dev_unchecked(),
                Duration::from_millis(300),
            );
            let _ = done_tx.send(());
            outcome
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
            "connect() is pinned by a dribbling daemon despite its timeout"
        );
        match worker.join().unwrap() {
            Err(ConnectError::Protocol(message)) => {
                assert!(
                    message.to_lowercase().contains("timed out"),
                    "expected a timeout diagnosis, got: {message}"
                );
            }
            Err(other) => panic!("expected a handshake protocol failure, got {other}"),
            Ok(client) => panic!(
                "a dribbling daemon must not complete connect: {:?}",
                client.hello()
            ),
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the refusal must arrive at the connect deadline"
        );
    }

    /// Consolidated round 3, item B: next_event reads were stateless, so a
    /// read that timed out mid-frame DISCARDED the partial bytes — the
    /// next call then misparsed the frame remainder as a fresh length
    /// prefix and desynchronized the stream. A call that expires must
    /// leave the partial frame resumable: the follow-up call completes
    /// the SAME event.
    #[test]
    fn next_event_resumes_a_partial_frame_after_a_timeout() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        use std::time::{Duration, Instant};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("split-event.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let Ok((mut peer, _)) = listener.accept() else {
                return;
            };
            let _ = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
            let _ = crate::frame::write_msg(
                &mut peer,
                &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                    protocol_version: 1,
                    daemon_version: "splitter".into(),
                    latest_event_seq: 0,
                }),
            );
            let mut frame = Vec::new();
            let _ = crate::frame::write_msg(
                &mut frame,
                &ServerMessage::Event(protonwire_frontend_api::EventEnvelope {
                    seq: 5,
                    event: protonwire_frontend_api::Event::Notice {
                        level: protonwire_frontend_api::NoticeLevel::Info,
                        message: "split across the deadline".into(),
                    },
                }),
            );
            assert!(frame.len() > 8, "fixture frame must be splittable");
            // Deliver 3 bytes (mid length-prefix), stall well past the
            // client timeout, then the rest.
            let _ = peer.write_all(&frame[..3]);
            let _ = peer.flush();
            std::thread::sleep(Duration::from_millis(700));
            let _ = peer.write_all(&frame[3..]);
            let _ = peer.flush();
            std::thread::sleep(Duration::from_secs(30));
        });

        let mut client = IpcClient::connect_with_timeout(
            &path,
            &test_client_info(),
            SecurityChecks::dev_unchecked(),
            Duration::from_millis(300),
        )
        .unwrap();

        // The first call expires while the frame is stalled.
        let started = Instant::now();
        let err = client
            .next_event()
            .expect_err("a stalled frame must expire at the client timeout");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "next_event overran its deadline on a stalled frame"
        );
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ),
            "expiry must surface as a timeout, got: {err}"
        );

        // The second call resumes the SAME frame — pre-fix it misparsed the
        // remainder as a fresh length prefix and desynchronized.
        match client.next_event() {
            Ok(envelope) => {
                assert_eq!(envelope.seq, 5, "the resumed frame must be event 5");
                match envelope.event {
                    protonwire_frontend_api::Event::Notice { message, .. } => {
                        assert_eq!(message, "split across the deadline")
                    }
                    other => panic!("expected the resumed notice, got {other:?}"),
                }
            }
            Err(e) => panic!("the partial frame must resume, got {e}"),
        }
    }

    /// Consolidated round 3, item B: next_event was unbounded against a
    /// DRIBBLING daemon — each socket read succeeds, so the per-syscall
    /// timeout never fires and the caller is pinned. The call is now
    /// deadline-bounded by the client timeout (documented policy: the
    /// expiry means "no event yet"; callers re-poll).
    #[test]
    fn next_event_is_bounded_against_an_ever_dribbling_daemon() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        use std::time::{Duration, Instant};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dribble-event.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let Ok((mut peer, _)) = listener.accept() else {
                return;
            };
            let _ = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
            let _ = crate::frame::write_msg(
                &mut peer,
                &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                    protocol_version: 1,
                    daemon_version: "dribbler".into(),
                    latest_event_seq: 0,
                }),
            );
            // Announce a plausible frame length, then dribble payload
            // bytes forever: no single read ever times out.
            let announced = 60_000u32.to_be_bytes();
            let _ = peer.write_all(&announced);
            let _ = peer.flush();
            let mut byte = b'x';
            loop {
                if peer.write_all(&[byte]).is_err() {
                    break;
                }
                let _ = peer.flush();
                byte = byte.wrapping_add(1);
                std::thread::sleep(Duration::from_millis(25));
            }
        });

        let mut client = IpcClient::connect_with_timeout(
            &path,
            &test_client_info(),
            SecurityChecks::dev_unchecked(),
            Duration::from_millis(300),
        )
        .unwrap();

        let started = Instant::now();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let outcome = client.next_event();
            let _ = done_tx.send(());
            outcome
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
            "next_event is pinned by an ever-dribbling daemon"
        );
        let err = worker.join().unwrap().expect_err("the dribble must expire");
        assert!(
            matches!(err.kind(), std::io::ErrorKind::TimedOut),
            "expiry must surface as TimedOut, got: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the expiry must arrive at the client deadline"
        );
    }

    /// QA mutation gap (item G3): discard_events_through had only indirect
    /// end-to-end coverage — the SDK's stale-skip also suppresses covered
    /// events, so REMOVING the discard call passed the suite. Direct unit:
    /// buffered events at or below the cursor must go, the queue must stay
    /// bounded, and the socket must keep delivering past the cursor.
    #[test]
    fn discard_events_through_bounds_the_pending_queue() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("discard.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let Ok((mut peer, _)) = listener.accept() else {
                return;
            };
            let _ = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
            let _ = crate::frame::write_msg(
                &mut peer,
                &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                    protocol_version: 1,
                    daemon_version: "discard".into(),
                    latest_event_seq: 0,
                }),
            );
            for seq in [5u64, 6] {
                let _ = crate::frame::write_msg(
                    &mut peer,
                    &ServerMessage::Event(protonwire_frontend_api::EventEnvelope {
                        seq,
                        event: protonwire_frontend_api::Event::Notice {
                            level: protonwire_frontend_api::NoticeLevel::Info,
                            message: format!("event {seq}"),
                        },
                    }),
                );
            }
            std::thread::sleep(Duration::from_secs(30));
        });

        let mut client = IpcClient::connect_with_timeout(
            &path,
            &test_client_info(),
            SecurityChecks::dev_unchecked(),
            Duration::from_secs(2),
        )
        .unwrap();

        // Events 3 and 4 sit in the buffer (as if they arrived mid-request
        // before a resync whose snapshot covered them); 5 and 6 are on the
        // wire behind them.
        for seq in [3u64, 4] {
            client.pending_events.push_back(EventEnvelope {
                seq,
                event: protonwire_frontend_api::Event::Notice {
                    level: protonwire_frontend_api::NoticeLevel::Info,
                    message: format!("stale {seq}"),
                },
            });
        }
        client.discard_events_through(4);
        assert!(
            client
                .pending_events
                .iter()
                .all(|envelope| envelope.seq > 4),
            "the pending queue must be bounded to events past the cursor"
        );
        assert_eq!(client.pending_events.len(), 0);

        // The next delivery is 5 — straight off the socket: the discard
        // cleared the covered events without touching the stream.
        let envelope = client.next_event().expect("socket event 5 arrives");
        assert_eq!(
            envelope.seq, 5,
            "delivery must resume at 5, not a stale one"
        );
        let envelope = client.next_event().expect("socket event 6 arrives");
        assert_eq!(envelope.seq, 6);
    }

    /// pr-champion round 6, WO-W3: events arriving while a request is in
    /// flight were push_back'ed into `pending_events` without bound — a
    /// daemon fanning out faster than the client re-enters `next_event`
    /// grew the queue for the whole request wait. The queue is capped
    /// (mirroring the daemon-side `bus::SESSION_QUEUE_LEN` = 256): overflow
    /// drops the OLDEST entry and bumps a counter surfaced by `next_event`;
    /// correctness after the induced seq gap is recovered by the existing
    /// latest_event_seq resync machinery, the counter is observability.
    ///
    /// FU-C (round-6 residual): none of that was pinned against the LOG —
    /// deleting `surface_pending_drops`' body passed the whole suite. The
    /// episodes below run under a capturing subscriber (hand-rolled: the
    /// crate has no tracing-subscriber dependency and only needs the WARN
    /// event's fields, not formatted output) and pin the one-shot warning:
    /// EXACTLY ONE overflow line per episode, the second episode warning
    /// carrying the cumulative total, and no line once the episode has been
    /// reported (the `unreported_drops` reset).
    #[test]
    fn request_event_burst_bounds_the_pending_queue_with_drop_accounting() {
        use std::os::unix::net::UnixListener;

        // 256 + 44: enough overflow to prove both the cap and the count.
        const EVENTS: u64 = PENDING_EVENTS_CAP as u64 + 44;
        // Two episodes: the burst fixture below repeats for each request.
        const EPISODES: u64 = 2;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("burst.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let Ok((mut peer, _)) = listener.accept() else {
                return;
            };
            let _ = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
            let _ = crate::frame::write_msg(
                &mut peer,
                &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                    protocol_version: 1,
                    daemon_version: "bursty".into(),
                    latest_event_seq: 0,
                }),
            );
            // One request/burst round per episode: swallow the request,
            // then a burst of events BEFORE the correlated response — the
            // exact arrival pattern of a fan-out during a long request
            // wait.
            for episode in 0..EPISODES {
                let request = crate::frame::read_msg::<_, ClientMessage>(&mut peer);
                for seq in episode * EVENTS + 1..=(episode + 1) * EVENTS {
                    let _ = crate::frame::write_msg(
                        &mut peer,
                        &ServerMessage::Event(EventEnvelope {
                            seq,
                            event: protonwire_frontend_api::Event::Notice {
                                level: protonwire_frontend_api::NoticeLevel::Info,
                                message: format!("burst {seq}"),
                            },
                        }),
                    );
                }
                if let Ok(ClientMessage::Request {
                    id,
                    request: Request::Ping { nonce },
                }) = request
                {
                    let _ = crate::frame::write_msg(
                        &mut peer,
                        &ServerMessage::Response(Response::Ok {
                            id,
                            result: RequestResult::Pong { nonce },
                        }),
                    );
                }
            }
            // Hold the socket: later reads must come from the buffer.
            std::thread::sleep(Duration::from_secs(30));
        });

        let mut client = IpcClient::connect_with_timeout(
            &path,
            &test_client_info(),
            SecurityChecks::dev_unchecked(),
            Duration::from_secs(5),
        )
        .unwrap();

        let capture = CaptureWarns::default();
        tracing::subscriber::with_default(capture.subscriber(), || {
            // Episode 1: the first burst overflows the cap by exactly the
            // first episode's surplus.
            match client
                .request(Request::Ping { nonce: "p1".into() })
                .expect("the correlated pong arrives after the burst")
            {
                RequestResult::Pong { nonce } => assert_eq!(nonce, "p1"),
                other => panic!("unexpected result: {other:?}"),
            }

            // The queue is bounded at the cap...
            assert_eq!(
                client.pending_events.len(),
                PENDING_EVENTS_CAP,
                "the pending queue must stay bounded under a mid-request burst"
            );
            // ...the OLDEST events were the ones dropped (1..=44 are gone,
            // 45..=300 remain in order)...
            assert_eq!(
                client.pending_events.front().expect("queue is full").seq,
                EVENTS + 1 - PENDING_EVENTS_CAP as u64,
                "overflow must drop the oldest buffered events"
            );
            assert_eq!(
                client.pending_events.back().expect("queue is full").seq,
                EVENTS,
                "the newest event must be retained"
            );
            // ...and the drop counter accounts for exactly the overflow.
            assert_eq!(
                client.dropped_events(),
                EVENTS - PENDING_EVENTS_CAP as u64,
                "the drop counter must account for every dropped event"
            );

            // The resync path still works over the bounded queue: a snapshot
            // through seq 299 covers all but the last event, and next_event
            // delivers it from the buffer — surfacing episode 1's drops as
            // exactly ONE warning.
            client.discard_events_through(EVENTS - 1);
            let envelope = client
                .next_event()
                .expect("the newest event still delivers after the resync discard");
            assert_eq!(envelope.seq, EVENTS);

            // Episode 2: a second burst against a queue drained by the
            // resync discard overflows it by the same surplus again; the
            // cumulative counter therefore doubles.
            match client
                .request(Request::Ping { nonce: "p2".into() })
                .expect("the second correlated pong arrives after the second burst")
            {
                RequestResult::Pong { nonce } => assert_eq!(nonce, "p2"),
                other => panic!("unexpected result: {other:?}"),
            }
            let per_episode = EVENTS - PENDING_EVENTS_CAP as u64;
            let expected_total = EPISODES * per_episode;
            assert_eq!(
                client.dropped_events(),
                expected_total,
                "the drop counter is cumulative across episodes"
            );
            // The second episode's first next_event surfaces the second
            // warning (with the cumulative total); one more delivery after
            // it must stay SILENT — the episode was already reported. The
            // queue's front is the oldest survivor of the second burst.
            let oldest_survivor = EPISODES * EVENTS - PENDING_EVENTS_CAP as u64 + 1;
            let envelope = client
                .next_event()
                .expect("the second episode still delivers buffered events");
            assert_eq!(envelope.seq, oldest_survivor);
            let envelope = client
                .next_event()
                .expect("buffered events keep delivering");
            assert_eq!(envelope.seq, oldest_survivor + 1);
        });

        // The one-shot pin: exactly one overflow warning per episode, the
        // second carrying the episode's own drops AND the cumulative
        // total — deleting the warn (zero lines) or the unreported_drops
        // reset (a third line, or a wrong second one) both fail here.
        let per_episode = EVENTS - PENDING_EVENTS_CAP as u64;
        let overflows = capture.overflow_warnings();
        assert_eq!(
            overflows,
            vec![
                (per_episode, per_episode),
                (per_episode, EPISODES * per_episode),
            ],
            "expected exactly one overflow warning per episode with the \
             cumulative totals, got: {overflows:?}"
        );
    }

    /// FU-C: a hand-rolled WARN-event capture. The crate deliberately has
    /// no tracing-subscriber dependency, so this implements the three
    /// required [`tracing::Subscriber`] methods directly and records only
    /// the fields the overflow warning carries — no formatted output, no
    /// filtering infrastructure, no new dependency.
    #[derive(Debug, Default)]
    struct CaptureWarns {
        overflows: Arc<Mutex<Vec<(u64, u64)>>>,
    }

    impl CaptureWarns {
        /// The subscriber to install via
        /// [`tracing::subscriber::with_default`]; it is consumed there,
        /// while `overflow_warnings` keeps reading through the shared
        /// handle.
        fn subscriber(&self) -> CaptureSubscriber {
            CaptureSubscriber {
                overflows: Arc::clone(&self.overflows),
            }
        }

        /// `(dropped, total)` pairs of every captured overflow warning, in
        /// emission order.
        fn overflow_warnings(&self) -> Vec<(u64, u64)> {
            self.overflows.lock().unwrap().clone()
        }
    }

    /// The subscriber half of [`CaptureWarns`].
    #[derive(Debug)]
    struct CaptureSubscriber {
        overflows: Arc<Mutex<Vec<(u64, u64)>>>,
    }

    impl tracing::Subscriber for CaptureSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            // The synchronous transport never creates spans; the trait
            // requires the method regardless.
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = OverflowFields::default();
            event.record(&mut fields);
            if fields.is_overflow {
                self.overflows
                    .lock()
                    .unwrap()
                    .push((fields.dropped, fields.total));
            }
        }
    }

    /// Field recorder for one event: flags the overflow warning by its
    /// message text and pulls its `dropped`/`total` counters.
    #[derive(Debug, Default)]
    struct OverflowFields {
        is_overflow: bool,
        dropped: u64,
        total: u64,
    }

    impl tracing::field::Visit for OverflowFields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message"
                && format!("{value:?}").contains("pending event queue overflowed")
            {
                self.is_overflow = true;
            }
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            match field.name() {
                "dropped" => self.dropped = value,
                "total" => self.total = value,
                _ => {}
            }
        }
    }
}
