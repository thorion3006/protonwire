//! Client-side IPC transport.
//!
//! Performs the trust checks a client must apply before speaking to the
//! daemon (PRD 6.3): the socket and its parent directory must be owned by
//! root and the directory must not be writable by group/others, so an
//! unprivileged user cannot plant a lookalike socket.

use std::collections::VecDeque;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use protonwire_frontend_api::{
    ClientInfo, ClientMessage, EventEnvelope, HelloAck, PROTOCOL_VERSION, Request, RequestResult,
    Response, RpcError, ServerMessage,
};

use crate::frame::{FrameError, FrameReader, write_msg};
use crate::peer::PeerCredentials;

/// Default request timeout.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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
    pending_events: VecDeque<EventEnvelope>,
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
        // The ceiling itself is the socket-wide SO_SNDTIMEO that
        // connect/set_timeout already applied (consolidated round 3, item
        // C: the two request-local re-arms were mutation-verified inert —
        // the write happens once at request start, where the remaining
        // budget differs from self.timeout only by microseconds). What
        // stays load-bearing is the zero-budget guard: a zero remainder
        // must not reach the write path, because a zero SO_SNDTIMEO means
        // "block forever" on Linux, not "fail immediately".
        let write_budget = deadline.saturating_duration_since(std::time::Instant::now());
        if write_budget.is_zero() {
            self.poisoned = true;
            return Err(RequestError::Transport(
                "request timed out without a response".into(),
            ));
        }
        write_msg(&mut self.stream, &ClientMessage::Request { id, request }).map_err(|e| {
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
            let outcome = self.reader.read_msg::<ServerMessage>();
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
}

fn map_frame_error(e: crate::frame::FrameError) -> io::Error {
    match e {
        crate::frame::FrameError::Io(io) => io,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

/// Verifies the daemon socket is root-owned and lives in a root-owned,
/// non-group/world-writable directory.
pub fn verify_socket_trusted(path: &Path) -> Result<(), ConnectError> {
    use std::os::unix::fs::FileTypeExt;
    let meta = std::fs::metadata(path).map_err(|source| ConnectError::Unreachable {
        path: path.to_owned(),
        source,
    })?;
    if !meta.file_type().is_socket() {
        return Err(ConnectError::Untrusted {
            path: path.to_owned(),
            reason: "path is not a socket".into(),
        });
    }
    if meta.uid() != 0 {
        return Err(ConnectError::Untrusted {
            path: path.to_owned(),
            reason: format!("socket owner UID {} is not root", meta.uid()),
        });
    }
    let parent = path.parent().unwrap_or(Path::new("/"));
    let parent_meta = std::fs::metadata(parent).map_err(|source| ConnectError::Untrusted {
        path: path.to_owned(),
        reason: format!("parent directory {} unreadable: {source}", parent.display()),
    })?;
    if parent_meta.uid() != 0 {
        return Err(ConnectError::Untrusted {
            path: path.to_owned(),
            reason: format!(
                "parent directory {} owner UID {} is not root",
                parent.display(),
                parent_meta.uid()
            ),
        });
    }
    if parent_meta.permissions().mode() & 0o022 != 0 {
        return Err(ConnectError::Untrusted {
            path: path.to_owned(),
            reason: format!(
                "parent directory {} is writable by group or others",
                parent.display()
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
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

    /// QA mutation gap (item G6): the zero-budget guard's failure mode is a
    /// HANG, not a wrong result. With a deadline already expired at the
    /// write (a sub-microsecond timeout makes `deadline - now` saturate to
    /// zero), the request must refuse to write at all — a zero-duration
    /// SO_SNDTIMEO means "block forever" on Linux, so without the guard
    /// the 0.86 MiB frame into a never-reading 4 KiB peer pins the
    /// caller indefinitely.
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
}
