//! Daemon-side IPC server: bind, authenticate, dispatch, fan out events.

use std::io;
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use protonwire_frontend_api::{
    ClientInfo, ClientMessage, HelloAck, HelloError, PROTOCOL_VERSION, Request, RequestResult,
    Response, RpcError, ServerMessage,
};
use tracing::{debug, info, warn};

use crate::authz::{authorize, required_role};
use crate::bus::EventBus;
use crate::frame::{FrameError, FrameReader, write_msg};
use crate::peer::PeerCredentials;

/// Interval at which session loops wake to check the stop flag while blocked
/// on reads.
const READ_POLL: Duration = Duration::from_millis(250);

/// A connection must complete the hello handshake within this window.
const HELLO_DEADLINE: Duration = Duration::from_secs(5);

/// Ceiling on blocked writes to one client; a peer that stops reading loses
/// its session instead of pinning a writer thread forever.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall ceiling on post-stop draining. `SO_SNDTIMEO` bounds each WRITE
/// syscall, not the shutdown join: a session that keeps dribbling reads (or
/// a handler that blocks) would otherwise hold `serve()` open indefinitely.
/// Three write ceilings: one blocked final write, one slow poll loop, and
/// one in-flight dispatch each get a full chance to finish.
const DRAIN_CEILING: Duration = Duration::from_secs(3 * WRITE_TIMEOUT.as_secs());

/// Timing budgets for one `serve()` invocation. Production uses the
/// defaults; tests inject shrunk values so drain and dribble scenarios run
/// in milliseconds instead of wall-clock seconds (QA robustness round 3).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServeBudgets {
    /// Window in which a connection must complete the hello handshake.
    pub(crate) hello_deadline: Duration,
    /// Overall ceiling on draining sessions after the stop flag is set.
    pub(crate) drain_ceiling: Duration,
}

impl Default for ServeBudgets {
    fn default() -> Self {
        Self {
            hello_deadline: HELLO_DEADLINE,
            drain_ceiling: DRAIN_CEILING,
        }
    }
}

/// What a session knows about its authenticated client.
#[derive(Debug, Clone)]
pub struct SessionContext {
    /// `SO_PEERCRED` identity of the client process.
    pub peer: PeerCredentials,
    /// Client-provided identity from the hello handshake.
    pub client: ClientInfo,
}

/// Daemon implementation of the request surface.
pub trait RequestHandler: Send + Sync {
    /// Daemon version reported in the hello acknowledgement.
    fn daemon_version(&self) -> &str;

    /// Sequence number of the newest event emitted so far.
    fn latest_event_seq(&self) -> u64;

    /// Executes one authenticated request.
    ///
    /// Bounded-dispatch contract: `handle` runs on the session's dispatch
    /// thread and must return promptly — well inside the 10 s
    /// [`WRITE_TIMEOUT`] ceiling. The server enforces an overall
    /// [`DRAIN_CEILING`] on shutdown draining: a handler still running past
    /// it gets its session socket forced down and its worker detached, so a
    /// blocking `handle` cannot pin `serve()` (but leaks its thread —
    /// long work belongs on a background task, with the response queued
    /// when it completes).
    fn handle(&self, ctx: &SessionContext, request: Request) -> Result<RequestResult, RpcError>;

    /// Event fan-out shared with the session loops.
    fn event_bus(&self) -> &EventBus;
}

/// A bound IPC server.
pub struct IpcServer {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl IpcServer {
    /// Binds `socket_dir/socket_name`.
    ///
    /// Creates the directory if missing, refuses to displace a live daemon's
    /// socket, and removes a stale socket file left by an unclean shutdown.
    /// The socket is created with mode `0o660`.
    pub fn bind(socket_dir: &Path, socket_name: &str) -> io::Result<Self> {
        std::fs::create_dir_all(socket_dir)?;
        let socket_path = socket_dir.join(socket_name);
        if socket_path.exists() {
            ensure_not_live(&socket_path)?;
            std::fs::remove_file(&socket_path)?;
        }
        let listener = UnixListener::bind(&socket_path)?;
        set_socket_mode(&socket_path)?;
        info!(path = %socket_path.display(), "IPC server bound");
        Ok(Self {
            listener,
            socket_path,
        })
    }

    /// The bound socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Accepts and serves sessions until `stop` is set, then returns.
    ///
    /// Each session runs on two threads (reader/dispatcher and writer) and is
    /// fully isolated: a misbehaving client only drops its own session.
    /// Sessions are bounded (64), must complete the handshake within 5 s,
    /// and cannot pin a writer past 10 s.
    ///
    /// Returning implies every session has DRAINED: responses queued before
    /// the stop flag — an administrator Shutdown acknowledgement, for
    /// example — are flushed to their sockets first (Codex PR review round
    /// 2, finding 4). A caller that exits when this returns therefore
    /// cannot lose a final response to process teardown. Draining is
    /// bounded overall by [`DRAIN_CEILING`] (3× the 10 s write ceiling):
    /// a session still owing data past it has its socket forced down and
    /// its worker detached, because `SO_SNDTIMEO` bounds each write
    /// syscall — not the shutdown join — and a slow-dribbling peer (or a
    /// blocking handler, see [`RequestHandler::handle`]) would otherwise
    /// pin `serve()` indefinitely.
    pub fn serve<H: RequestHandler + 'static>(&self, handler: Arc<H>, stop: Arc<AtomicBool>) {
        self.serve_with(handler, stop, ServeBudgets::default());
    }

    /// [`IpcServer::serve`] with injectable timing budgets (tests shrink
    /// them; production always goes through the defaults).
    pub(crate) fn serve_with<H: RequestHandler + 'static>(
        &self,
        handler: Arc<H>,
        stop: Arc<AtomicBool>,
        budgets: ServeBudgets,
    ) {
        // Poll-accept so shutdown is responsive without signal plumbing here.
        if let Err(e) = self.listener.set_nonblocking(true) {
            warn!("cannot switch accept loop to nonblocking mode: {e}");
            return;
        }
        let mut sessions: Vec<SessionWorker> = Vec::new();
        while !stop.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    // Reserve the session slot ATOMICALLY, before the worker
                    // is spawned: checking the subscriber count here races a
                    // concurrent burst, because the connection only
                    // registers once the spawned thread runs (Codex PR
                    // review finding 2).
                    if !handler.event_bus().try_reserve_session() {
                        debug!("session limit reached; dropping new connection");
                        continue; // dropping `stream` closes it
                    }
                    // The socket is owned by the session worker; the drain
                    // loop below keeps only a weak handle so a session that
                    // outlives the ceiling can still be forced down.
                    let stream = Arc::new(stream);
                    let session_stream = Arc::downgrade(&stream);
                    let handler = Arc::clone(&handler);
                    let stop = Arc::clone(&stop);
                    let join = std::thread::spawn(move || {
                        if let Err(e) = std::panic::catch_unwind(AssertUnwindSafe(|| {
                            handle_session(stream, handler, stop, budgets.hello_deadline)
                        })) {
                            warn!("IPC session panicked and was dropped: {e:?}");
                        }
                    });
                    sessions.push(SessionWorker {
                        join,
                        stream: session_stream,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(READ_POLL);
                }
                Err(e) => {
                    warn!("accept failed: {e}");
                    std::thread::sleep(READ_POLL);
                }
            }
        }
        let drain_deadline = Instant::now() + budgets.drain_ceiling;
        // Codex PR review round 2, finding 4: the session workers are
        // detached from the accept loop, and a handler can publish the
        // stop flag BEFORE its response is queued (the Shutdown path).
        // Returning without joining let the daemon's main exit while a
        // writer still owed its client a final acknowledgement. Joining
        // every session makes serve()'s return mean "all sessions torn
        // down and their queued responses flushed".
        while sessions.iter().any(|session| !session.join.is_finished()) {
            if Instant::now() >= drain_deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        for session in sessions {
            if session.join.is_finished() {
                let _ = session.join;
                continue;
            }
            // Past the ceiling the straggler is forced down and detached:
            // the shutdown errors its blocked writer (and ends the client's
            // wait) instead of waiting out a dribbling peer, while a worker
            // stuck inside a blocking handler is abandoned to finish (or
            // leak its thread) on its own — serve() must return regardless.
            // An expired weak handle needs no forcing: the session already
            // released its socket.
            if let Some(stream) = session.stream.upgrade() {
                warn!("drain ceiling exceeded; forcing a session socket down");
                let _ = stream.shutdown(Shutdown::Both);
            }
            drop(session.join);
        }
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// One accepted session as seen from the accept loop: its worker thread
/// plus a weak handle on the session socket, so the drain phase can force
/// a straggler down once the ceiling passes. The handle is deliberately
/// WEAK — the session worker owns the socket, and holding a strong
/// reference here would keep the fd open (and the client without its EOF)
/// until the whole server stops.
struct SessionWorker {
    join: std::thread::JoinHandle<()>,
    stream: std::sync::Weak<UnixStream>,
}

/// Whether a connect failure definitively identifies a stale socket file
/// and therefore authorizes removing it (Codex PR review finding 11).
///
/// `ECONNREFUSED` is the only such signal: a stream socket with no
/// listener refuses immediately. Every other failure (descriptor
/// exhaustion, `EACCES`, ...) is inconclusive — the socket may belong to
/// a live but unreachable daemon — and must abort startup instead of
/// unlinking it and letting a second daemon bind the same path.
fn authorizes_unlink(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::ConnectionRefused
}

/// Refuses to remove a socket another daemon is actively serving.
fn ensure_not_live(socket_path: &Path) -> io::Result<()> {
    // Local Unix sockets connect immediately; only a REFUSED connect
    // proves no live listener owns the path. Inconclusive errors are
    // returned so `bind` fails loudly instead of unlinking.
    match UnixStream::connect(socket_path) {
        Ok(_) => Err(io::Error::other(format!(
            "another daemon is serving {}",
            socket_path.display()
        ))),
        Err(e) if authorizes_unlink(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

fn set_socket_mode(socket_path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))
}

/// Serves one client connection until EOF, error, or daemon shutdown.
fn handle_session<H: RequestHandler>(
    stream: Arc<UnixStream>,
    handler: Arc<H>,
    stop: Arc<AtomicBool>,
    hello_deadline: Duration,
) {
    // The session slot the accept loop reserved is released on EVERY exit
    // path — early rejects below, dispatcher panics (the serve loop's
    // catch_unwind drops this guard during unwind), and normal teardown
    // (Codex PR review finding 2).
    struct ReleaseSlotOnDrop<'a>(&'a EventBus);
    impl Drop for ReleaseSlotOnDrop<'_> {
        fn drop(&mut self) {
            self.0.release_session();
        }
    }
    let _slot = ReleaseSlotOnDrop(handler.event_bus());
    let Ok(peer) = PeerCredentials::of(&stream) else {
        debug!("session rejected: peer credentials unavailable");
        return;
    };
    if let Err(e) = stream.set_read_timeout(Some(READ_POLL)) {
        warn!("set_read_timeout failed: {e}");
        return;
    };
    let Ok(mut read_half) = stream.try_clone() else {
        warn!("session rejected: socket clone failed");
        return;
    };

    // Writer thread owns a socket handle exclusively; a write timeout bounds
    // how long a non-reading peer can pin it. Socket options are shared with
    // every clone of the socket, so the timeouts set here govern the reader
    // and the drain handle alike.
    if let Err(e) = stream.set_write_timeout(Some(WRITE_TIMEOUT)) {
        warn!("set_write_timeout failed: {e}");
        return;
    }
    let (writer_tx, writer_rx) = mpsc::sync_channel::<ServerMessage>(crate::bus::SESSION_QUEUE_LEN);
    let write_stream = stream;
    let writer = std::thread::spawn(move || {
        let mut write_half = &*write_stream;
        for message in writer_rx {
            if write_msg(&mut write_half, &message).is_err() {
                break;
            }
        }
    });

    let (session_id, event_rx) = handler.event_bus().subscribe();
    // Drop-guard: unsubscribe runs on every exit path, including panics in
    // the dispatcher below.
    struct UnsubscribeOnDrop<'a> {
        bus: &'a EventBus,
        id: u64,
    }
    impl Drop for UnsubscribeOnDrop<'_> {
        fn drop(&mut self) {
            self.bus.unsubscribe(self.id);
        }
    }
    let _guard = UnsubscribeOnDrop {
        bus: handler.event_bus(),
        id: session_id,
    };
    let event_forward = {
        let forward_tx = writer_tx.clone();
        std::thread::spawn(move || {
            for message in event_rx {
                if forward_tx.send(message).is_err() {
                    break;
                }
            }
        })
    };

    let result = serve_messages(
        &mut read_half,
        &writer_tx,
        &handler,
        &peer,
        &stop,
        hello_deadline,
    );
    // Teardown order is load-bearing: dropping our sender alone is not
    // enough — the forwarder holds a clone — so we must unsubscribe BEFORE
    // joining. Unsubscribe closes the bus sender, which ends the forwarder,
    // which drops the last writer-sender clone, which ends the writer.
    // Joining first deadlocks and leaks the session slot plus both threads
    // (rust-review finding 1).
    drop(writer_tx);
    drop(_guard);
    let _ = writer.join();
    let _ = event_forward.join();
    debug!(uid = peer.uid, outcome = ?result, "session closed");
}

/// Handshake + request loop for one session.
fn serve_messages(
    read_half: &mut UnixStream,
    writer_tx: &mpsc::SyncSender<ServerMessage>,
    handler: &Arc<impl RequestHandler>,
    peer: &PeerCredentials,
    stop: &AtomicBool,
    hello_deadline: Duration,
) -> Result<(), FrameError> {
    let mut reader = FrameReader::new(read_half);
    let connected_at = Instant::now();
    let mut hello_done = false;
    let mut client_info = None;
    while !stop.load(Ordering::SeqCst) {
        if !hello_done && connected_at.elapsed() > hello_deadline {
            let _ = writer_tx.send(ServerMessage::HelloError(HelloError {
                supported_version: PROTOCOL_VERSION,
                reason: "hello-timeout".into(),
            }));
            return Ok(());
        }
        // Codex PR review round 2, finding 2: the deadline must hold DURING
        // a frame too. A peer trickling one byte per sub-READ_POLL interval
        // keeps every individual read succeeding, so the loop above is not
        // revisited until the frame completes — a dribbled hello could hold
        // its reserved session slot indefinitely. The codec-level deadline
        // fails the read with TimedOut, which the arm below treats as
        // pollable; the check at the top of the loop then issues the
        // hello-timeout refusal. Post-hello reads are unbounded: a live
        // session may take as long as its client needs between requests.
        let message = match if hello_done {
            reader.read_msg::<ClientMessage>()
        } else {
            reader.read_msg_within::<ClientMessage>(connected_at + hello_deadline)
        } {
            Ok(m) => m,
            Err(FrameError::Io(e))
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        match message {
            ClientMessage::Hello {
                protocol_version,
                client,
            } => {
                if hello_done {
                    let _ = writer_tx.send(ServerMessage::HelloError(HelloError {
                        supported_version: PROTOCOL_VERSION,
                        reason: "duplicate-hello".into(),
                    }));
                    return Ok(());
                }
                if protocol_version > PROTOCOL_VERSION || protocol_version < 1 {
                    let _ = writer_tx.send(ServerMessage::HelloError(HelloError {
                        supported_version: PROTOCOL_VERSION,
                        reason: "unsupported-protocol-version".into(),
                    }));
                    return Ok(());
                }
                let client = client.sanitized();
                info!(uid = peer.uid, name = %client.name, "client connected");
                if writer_tx
                    .send(ServerMessage::HelloAck(HelloAck {
                        // Speak the highest version both sides support.
                        protocol_version: protocol_version.min(PROTOCOL_VERSION),
                        daemon_version: handler.daemon_version().to_owned(),
                        latest_event_seq: handler.latest_event_seq(),
                    }))
                    .is_err()
                {
                    // The writer is gone; a client waiting on the ack would
                    // otherwise hang until its own timeout (rust-review
                    // finding 11).
                    return Ok(());
                }
                client_info = Some(client);
                hello_done = true;
            }
            ClientMessage::Request { id, request } => {
                let Some(client) = client_info.as_ref() else {
                    let _ = writer_tx.send(ServerMessage::HelloError(HelloError {
                        supported_version: PROTOCOL_VERSION,
                        reason: "request-before-hello".into(),
                    }));
                    return Ok(());
                };
                let ctx = SessionContext {
                    peer: *peer,
                    client: client.clone(),
                };
                let response = match dispatch(handler, &ctx, request) {
                    Ok(result) => Response::Ok { id, result },
                    Err(error) => Response::Error { id, error },
                };
                if writer_tx.send(ServerMessage::Response(response)).is_err() {
                    return Ok(()); // writer is gone; nothing more to do
                }
            }
        }
    }
    Ok(())
}

/// Authorization plus handler execution for one request.
fn dispatch(
    handler: &Arc<impl RequestHandler>,
    ctx: &SessionContext,
    request: Request,
) -> Result<RequestResult, RpcError> {
    authorize(required_role(&request), &ctx.peer)?;
    handler.handle(ctx, request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::MAX_SESSIONS;
    use crate::frame::{read_msg, write_msg};
    use protonwire_frontend_api::{ClientInfo, ClientSurface, Request};

    use std::sync::Arc;
    use std::time::{Duration, Instant};

    struct NullHandler {
        version: String,
        bus: EventBus,
    }

    impl RequestHandler for NullHandler {
        fn daemon_version(&self) -> &str {
            &self.version
        }
        fn latest_event_seq(&self) -> u64 {
            0
        }
        fn handle(
            &self,
            _ctx: &SessionContext,
            request: Request,
        ) -> Result<RequestResult, RpcError> {
            let _ = request;
            Err(RpcError::new(
                protonwire_frontend_api::RpcErrorCode::NotImplemented,
                "test handler",
            ))
        }
        fn event_bus(&self) -> &EventBus {
            &self.bus
        }
    }

    fn info() -> ClientInfo {
        ClientInfo {
            name: "server-test".into(),
            version: "0".into(),
            surface: ClientSurface::Other,
        }
    }

    fn spawn_server(
        dir: &tempfile::TempDir,
        handler: Arc<NullHandler>,
    ) -> crate::test_util::TestServer {
        crate::test_util::TestServer::start(dir.path(), "server-test.sock", handler)
            .expect("test server binds")
    }

    fn connect_and_hello(path: &std::path::Path) -> std::os::unix::net::UnixStream {
        let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
        write_msg(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: 1,
                client: info(),
            },
        )
        .unwrap();
        // Wait for the ack so the session is fully established.
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloAck(_) => stream,
            other => panic!("expected hello ack, got {other:?}"),
        }
    }

    /// Regression (rust-review finding 1): every ended session must
    /// release its bus slot and session threads. The pre-fix teardown
    /// joined the writer before unsubscribing, deadlocking on the
    /// forwarder's sender clone — leaking a slot and two threads per
    /// session until MAX_SESSIONS wedged the daemon permanently.
    #[test]
    fn ended_sessions_release_their_bus_slot() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, Arc::clone(&handler));
        let path = server.socket_path().to_owned();

        for _ in 0..8 {
            drop(connect_and_hello(&path));
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        while handler.event_bus().session_count() != 0 {
            assert!(
                Instant::now() < deadline,
                "sessions leaked: {} slot(s) still subscribed after all clients \
                 disconnected — teardown is deadlocked again",
                handler.event_bus().session_count()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while handler.event_bus().active_sessions() != 0 {
            assert!(
                Instant::now() < deadline,
                "session slots leaked: {} still reserved after all clients \
                 disconnected",
                handler.event_bus().active_sessions()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Codex PR review finding 2 (P1): MAX_SESSIONS was checked against
    /// bus.session_count() only after the connection was accepted and the
    /// worker spawned, so a concurrent burst — none of the spawned threads
    /// having subscribed yet — sailed past the 64-session ceiling. The cap
    /// must hold under a burst, not only sequentially.
    #[test]
    fn concurrent_connection_burst_never_exceeds_the_session_cap() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, Arc::clone(&handler));
        let path = server.socket_path().to_owned();

        // 3x the cap, all connecting at once and never handshaking: every
        // accepted connection occupies a session until the 5 s hello
        // deadline, so the live count is directly observable. The sockets
        // stay open (held in `streams`) for the whole measurement.
        const BURST: usize = MAX_SESSIONS * 3;
        let (tx, rx) = mpsc::channel::<std::os::unix::net::UnixStream>();
        let connect_error = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for _ in 0..BURST {
            let path = path.clone();
            let tx = tx.clone();
            let connect_error = Arc::clone(&connect_error);
            std::thread::spawn(
                move || match std::os::unix::net::UnixStream::connect(&path) {
                    Ok(stream) => {
                        let _ = tx.send(stream);
                    }
                    Err(_) => {
                        connect_error.fetch_add(1, Ordering::SeqCst);
                    }
                },
            );
        }
        drop(tx);
        let mut streams = Vec::new();
        while let Ok(stream) = rx.recv() {
            streams.push(stream);
        }
        assert_eq!(
            connect_error.load(Ordering::SeqCst),
            0,
            "the burst must fit the listen backlog"
        );

        // Accept-loop drain plus session setup, still well inside the 5 s
        // hello deadline that keeps unhandshaken sessions alive.
        std::thread::sleep(Duration::from_millis(750));
        let live = handler.event_bus().session_count();
        let reserved = handler.event_bus().active_sessions();
        assert!(
            live <= MAX_SESSIONS && reserved <= MAX_SESSIONS,
            "session ceiling violated under a concurrent burst: {live} live / \
             {reserved} reserved sessions, cap is {MAX_SESSIONS}"
        );
        drop(server);
        drop(streams);
    }

    /// Finding 10: the handshake must reject versions below the oldest
    /// supported protocol (1), not ack them into a lie.
    #[test]
    fn hello_below_oldest_supported_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, handler);
        let mut stream = std::os::unix::net::UnixStream::connect(server.socket_path()).unwrap();
        write_msg(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: 0,
                client: info(),
            },
        )
        .unwrap();
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloError(err) => {
                assert_eq!(err.reason, "unsupported-protocol-version");
                assert_eq!(err.supported_version, 1);
            }
            other => panic!("expected HelloError for version 0, got {other:?}"),
        }
    }

    /// Characterization (refactorer step 2): the handshake refusals that
    /// M2's protocol-negotiation work will edit around. Each pins the
    /// exact wire behavior of `serve_messages` through the public socket.
    #[test]
    fn hello_above_ceiling_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, handler);
        let mut stream = std::os::unix::net::UnixStream::connect(server.socket_path()).unwrap();
        write_msg(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: 99,
                client: info(),
            },
        )
        .unwrap();
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloError(err) => {
                assert_eq!(err.reason, "unsupported-protocol-version");
                assert_eq!(err.supported_version, PROTOCOL_VERSION);
            }
            other => panic!("expected HelloError for version 99, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_hello_is_refused_and_disconnected() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, handler);
        let mut stream = connect_and_hello(server.socket_path());
        write_msg(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: 1,
                client: info(),
            },
        )
        .unwrap();
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloError(err) => assert_eq!(err.reason, "duplicate-hello"),
            other => panic!("expected HelloError for duplicate hello, got {other:?}"),
        }
        // The session ends: the next read hits EOF.
        assert!(matches!(
            read_msg::<_, ServerMessage>(&mut stream),
            Err(crate::frame::FrameError::Truncated)
        ));
    }

    #[test]
    fn request_before_hello_is_refused_and_disconnected() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, handler);
        let mut stream = std::os::unix::net::UnixStream::connect(server.socket_path()).unwrap();
        write_msg(
            &mut stream,
            &ClientMessage::Request {
                id: 1,
                request: Request::GetState,
            },
        )
        .unwrap();
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloError(err) => assert_eq!(err.reason, "request-before-hello"),
            other => panic!("expected HelloError for early request, got {other:?}"),
        }
        assert!(matches!(
            read_msg::<_, ServerMessage>(&mut stream),
            Err(crate::frame::FrameError::Truncated)
        ));
    }

    #[test]
    fn negotiated_version_is_min_of_client_and_server() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, handler);
        let mut stream = std::os::unix::net::UnixStream::connect(server.socket_path()).unwrap();
        write_msg(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: 1,
                client: info(),
            },
        )
        .unwrap();
        // A client at the oldest supported version negotiates exactly it;
        // when PROTOCOL_VERSION grows, offering 1 must still ack 1.
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloAck(ack) => assert_eq!(ack.protocol_version, 1),
            other => panic!("expected HelloAck, got {other:?}"),
        }
    }

    /// Codex PR review finding 5 (P2; tracked as rust-review #12): a peer
    /// that writes part of a frame, pauses longer than the 250 ms read
    /// poll, then writes the rest must NOT desynchronize the session. The
    /// pre-fix stateless read discarded the partial bytes on WouldBlock
    /// and re-read the remainder as a fresh length prefix.
    #[test]
    fn partial_frame_across_read_timeouts_stays_synchronized() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, handler);
        let mut stream = std::os::unix::net::UnixStream::connect(server.socket_path()).unwrap();

        // Serialize the hello frame, deliver 3 prefix bytes, stall past
        // READ_POLL, then the rest.
        let mut frame = Vec::new();
        write_msg(
            &mut frame,
            &ClientMessage::Hello {
                protocol_version: 1,
                client: info(),
            },
        )
        .unwrap();
        assert!(frame.len() > 8);
        stream.write_all(&frame[..3]).unwrap();
        stream.flush().unwrap();
        std::thread::sleep(READ_POLL * 3);
        stream.write_all(&frame[3..]).unwrap();
        stream.flush().unwrap();

        // The session must still parse the hello and answer the ack.
        match read_msg::<_, ServerMessage>(&mut stream) {
            Ok(ServerMessage::HelloAck(_)) => {}
            other => panic!("expected HelloAck after a split frame, got {other:?}"),
        }
        // ...and stay synchronized for a follow-up exchange.
        write_msg(
            &mut stream,
            &ClientMessage::Request {
                id: 7,
                request: Request::GetState,
            },
        )
        .unwrap();
        match read_msg::<_, ServerMessage>(&mut stream) {
            Ok(ServerMessage::Response(response)) => assert_eq!(response.id(), 7),
            other => panic!("expected a correlated response, got {other:?}"),
        }
    }

    /// Codex PR review round 2, finding 2 (P2): HELLO_DEADLINE was only
    /// re-checked between COMPLETE frames. A peer that supplies one byte
    /// before each 250 ms read timeout keeps `FrameReader`'s inner fill
    /// loop satisfied — no error ever surfaces — so a maximum-sized hello
    /// could dribble for hours while holding a reserved session slot.
    /// The hello-phase read must fail once the deadline passes even while
    /// bytes keep arriving.
    ///
    /// QA robustness (consolidated round 3, item H): the deadline is
    /// injected at 500 ms and the dribble runs 25 ms/byte — the same
    /// behavioral claim at a tenth of the wall clock and far more tolerant
    /// of a loaded test machine (the margin between the dribble pace and
    /// the deadline is what the assertion needs, not absolute seconds).
    #[test]
    fn hello_deadline_holds_against_a_steady_byte_dribble() {
        use std::io::Write;
        use std::time::{Duration, Instant};

        const DRIBBLE_MS_PER_BYTE: u64 = 25;
        let hello_deadline = Duration::from_millis(500);

        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let server = IpcServer::bind(dir.path(), "dribble.sock").unwrap();
        let stop_flag = Arc::clone(&stop);
        std::thread::spawn(move || {
            server.serve_with(
                handler,
                stop_flag,
                ServeBudgets {
                    hello_deadline,
                    ..ServeBudgets::default()
                },
            )
        });
        let stream =
            std::os::unix::net::UnixStream::connect(dir.path().join("dribble.sock")).unwrap();
        let mut read_half = stream.try_clone().unwrap();
        let mut write_half = stream;

        let mut frame = Vec::new();
        write_msg(
            &mut frame,
            &ClientMessage::Hello {
                protocol_version: 1,
                client: info(),
            },
        )
        .unwrap();
        // The dribble would complete this frame in well over double the
        // deadline, and no single read ever hits the 250 ms poll timeout —
        // the exact shape of the claimed dribble.
        assert!(
            frame.len() as u64 * DRIBBLE_MS_PER_BYTE > hello_deadline.as_millis() as u64 * 2,
            "fixture frame must out-dribble the deadline"
        );

        let dribbler = std::thread::spawn(move || {
            for byte in frame {
                if write_half.write_all(&[byte]).is_err() {
                    break; // the server hung up mid-dribble
                }
                let _ = write_half.flush();
                std::thread::sleep(Duration::from_millis(DRIBBLE_MS_PER_BYTE));
            }
        });

        read_half
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let started = Instant::now();
        match read_msg::<_, ServerMessage>(&mut read_half) {
            Ok(ServerMessage::HelloError(err)) => {
                assert_eq!(err.reason, "hello-timeout");
                assert!(
                    started.elapsed() < hello_deadline + Duration::from_secs(1),
                    "refusal arrived well past the deadline"
                );
            }
            other => panic!("expected a hello-timeout refusal, got {other:?}"),
        }
        // The session ends after the refusal.
        assert!(matches!(
            read_msg::<_, ServerMessage>(&mut read_half),
            Err(crate::frame::FrameError::Truncated)
        ));
        dribbler.join().unwrap();
        stop.store(true, Ordering::SeqCst);
    }

    /// Codex PR review round 2, finding 4 (P2): an administrator Shutdown
    /// sets the stop flag BEFORE the session queues its acknowledgement.
    /// The accept loop observes the flag and returns, and the daemon's
    /// main exits with the detached session workers dying mid-flush —
    /// `protonwire daemon stop` can report a transport failure for a
    /// shutdown that succeeded. serve() must not return until every
    /// session has drained, so a caller that exits on its return cannot
    /// lose a queued final response.
    #[test]
    fn serve_returns_only_after_sessions_flushed_their_final_responses() {
        use std::time::{Duration, Instant};

        /// Mirrors DaemonHandler's Shutdown ordering: the stop flag is
        /// published BEFORE the response is returned, and the handler is
        /// slow to answer so the accept loop observes the flag while the
        /// session is still mid-dispatch.
        struct StopThenSlowPong {
            bus: Arc<EventBus>,
            stop: Arc<AtomicBool>,
        }
        impl RequestHandler for StopThenSlowPong {
            fn daemon_version(&self) -> &str {
                "test"
            }
            fn latest_event_seq(&self) -> u64 {
                0
            }
            fn handle(
                &self,
                _ctx: &SessionContext,
                request: Request,
            ) -> Result<RequestResult, RpcError> {
                match request {
                    Request::Ping { nonce } => {
                        self.stop.store(true, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(900));
                        Ok(RequestResult::Pong { nonce })
                    }
                    _ => Err(RpcError::new(
                        protonwire_frontend_api::RpcErrorCode::NotImplemented,
                        "test handler",
                    )),
                }
            }
            fn event_bus(&self) -> &EventBus {
                &self.bus
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let bus = Arc::new(EventBus::new());
        let stop = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(StopThenSlowPong {
            bus: Arc::clone(&bus),
            stop: Arc::clone(&stop),
        });
        let server = IpcServer::bind(dir.path(), "drain.sock").unwrap();
        let path = server.socket_path().to_owned();
        let served = std::thread::spawn(move || server.serve(handler, stop));

        let mut stream = connect_and_hello(&path);
        write_msg(
            &mut stream,
            &ClientMessage::Request {
                id: 42,
                request: Request::Ping {
                    nonce: "stop".into(),
                },
            },
        )
        .unwrap();

        // The accept loop sees the flag within one READ_POLL (~250 ms)
        // while the handler still sleeps — pre-fix, serve() returned with
        // the acknowledgement not even queued.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !served.is_finished() {
            assert!(
                Instant::now() < deadline,
                "serve() did not return after the stop flag"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(
            bus.active_sessions(),
            0,
            "serve() returned while a session was still draining — its \
             queued response can be lost to process exit"
        );
        // The guarantee `protonwire daemon stop` depends on: the
        // acknowledgement is on the wire before the caller proceeds.
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::Response(response) => assert_eq!(response.id(), 42),
            other => panic!("expected the drained acknowledgement, got {other:?}"),
        }
        let _ = served.join();
    }

    /// Consolidated round 3 (rust-reviewer + sec-auditor, item A): the
    /// round-2 drain fix joined every session worker, but `SO_SNDTIMEO`
    /// bounds each WRITE syscall — not the join. A handshaken session
    /// whose client never reads and whose final response exceeds the
    /// socket buffers pins the join for the full 10 s write ceiling, and a
    /// future blocking handler would pin it forever. Draining needs an
    /// overall ceiling: past it, the straggler's socket is forced down
    /// and the join abandoned.
    #[test]
    fn serve_returns_within_the_drain_ceiling_when_a_writer_is_pinned() {
        use std::time::{Duration, Instant};

        /// Stop-then-pong, but the pong is far larger than the socket
        /// buffers of a client that never reads.
        struct StopThenHugePong {
            bus: Arc<EventBus>,
            stop: Arc<AtomicBool>,
        }
        impl RequestHandler for StopThenHugePong {
            fn daemon_version(&self) -> &str {
                "test"
            }
            fn latest_event_seq(&self) -> u64 {
                0
            }
            fn handle(
                &self,
                _ctx: &SessionContext,
                request: Request,
            ) -> Result<RequestResult, RpcError> {
                match request {
                    Request::Ping { nonce } => {
                        self.stop.store(true, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(200));
                        Ok(RequestResult::Pong { nonce })
                    }
                    _ => Err(RpcError::new(
                        protonwire_frontend_api::RpcErrorCode::NotImplemented,
                        "test handler",
                    )),
                }
            }
            fn event_bus(&self) -> &EventBus {
                &self.bus
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let bus = Arc::new(EventBus::new());
        let stop = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(StopThenHugePong {
            bus: Arc::clone(&bus),
            stop: Arc::clone(&stop),
        });
        let server = IpcServer::bind(dir.path(), "drain-pin.sock").unwrap();
        let path = server.socket_path().to_owned();
        let ceiling = Duration::from_millis(600);
        let served = std::thread::spawn(move || {
            server.serve_with(
                handler,
                stop,
                ServeBudgets {
                    drain_ceiling: ceiling,
                    ..ServeBudgets::default()
                },
            )
        });

        // Handshake normally, then shrink our receive buffer and never read
        // again: the ~0.86 MiB pong cannot fit and pins the session writer.
        let mut stream = connect_and_hello(&path);
        set_rcvbuf(&stream, 4096);
        write_msg(
            &mut stream,
            &ClientMessage::Request {
                id: 7,
                request: Request::Ping {
                    nonce: "x".repeat(900_000),
                },
            },
        )
        .unwrap();

        // Pre-fix, serve() waited out the writer's full 10 s write ceiling
        // (or forever for a blocked handler); the bound must be the
        // injected drain ceiling plus polling slack.
        let started = Instant::now();
        while !served.is_finished() {
            assert!(
                Instant::now() < started + ceiling + Duration::from_secs(2),
                "serve() is pinned past the drain ceiling by a blocked writer"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            started.elapsed() < ceiling + Duration::from_secs(2),
            "serve() overran the drain ceiling: {} ms",
            started.elapsed().as_millis()
        );
        let _ = served.join();
    }

    /// QA mutation gap (item G7): the drain must join EVERY owing session,
    /// not just the most recent one. With N sessions each owing a final
    /// response at stop time, serve()'s return must find all of them torn
    /// down — a join-the-last mutation returns with the slower sessions
    /// still draining, losing their queued responses to process exit.
    #[test]
    fn serve_drains_every_owing_session_not_just_the_last() {
        use std::time::{Duration, Instant};

        /// Answers pings after a per-request delay; the delay shrinks with
        /// the request id so the FIRST session is the slowest to drain.
        struct SlowPongById {
            bus: Arc<EventBus>,
        }
        impl RequestHandler for SlowPongById {
            fn daemon_version(&self) -> &str {
                "test"
            }
            fn latest_event_seq(&self) -> u64 {
                0
            }
            fn handle(
                &self,
                _ctx: &SessionContext,
                request: Request,
            ) -> Result<RequestResult, RpcError> {
                match request {
                    Request::Ping { nonce } => {
                        let delay = match nonce.parse::<u64>() {
                            Ok(id) => Duration::from_millis(900 - 200 * id),
                            Err(_) => Duration::from_millis(100),
                        };
                        std::thread::sleep(delay);
                        Ok(RequestResult::Pong { nonce })
                    }
                    _ => Err(RpcError::new(
                        protonwire_frontend_api::RpcErrorCode::NotImplemented,
                        "test handler",
                    )),
                }
            }
            fn event_bus(&self) -> &EventBus {
                &self.bus
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let bus = Arc::new(EventBus::new());
        let stop = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(SlowPongById {
            bus: Arc::clone(&bus),
        });
        let server = IpcServer::bind(dir.path(), "drain-multi.sock").unwrap();
        let path = server.socket_path().to_owned();
        let stop_flag = Arc::clone(&stop);
        let served = std::thread::spawn(move || server.serve(handler, stop_flag));

        // Connect every client BEFORE any handshake so the accept loop
        // picks all four up in one burst (sequential connects would
        // quantize on its 250 ms poll and blur who drains last).
        const SESSIONS: usize = 4;
        let mut streams: Vec<std::os::unix::net::UnixStream> = (0..SESSIONS)
            .map(|_| std::os::unix::net::UnixStream::connect(&path).unwrap())
            .collect();
        for (id, stream) in streams.iter_mut().enumerate() {
            write_msg(
                stream,
                &ClientMessage::Hello {
                    protocol_version: 1,
                    client: info(),
                },
            )
            .unwrap();
            match read_msg::<_, ServerMessage>(stream).unwrap() {
                ServerMessage::HelloAck(_) => {}
                other => panic!("expected hello ack, got {other:?}"),
            }
            write_msg(
                stream,
                &ClientMessage::Request {
                    id: id as u64,
                    request: Request::Ping {
                        nonce: id.to_string(),
                    },
                },
            )
            .unwrap();
        }
        // Every ping is dispatched and sleeping before the flag drops, so
        // all four sessions owe their pong at stop time; the first (900 ms
        // delay) is the last to drain, the fourth (300 ms) the first.
        std::thread::sleep(Duration::from_millis(400));
        stop.store(true, Ordering::SeqCst);

        let deadline = Instant::now() + Duration::from_secs(10);
        while !served.is_finished() {
            assert!(
                Instant::now() < deadline,
                "serve() did not return after stop"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(
            bus.active_sessions(),
            0,
            "serve() returned while sessions were still draining — a \
             join-the-last mutation loses their queued final responses"
        );
        for (id, stream) in streams.iter_mut().enumerate() {
            match read_msg::<_, ServerMessage>(stream).unwrap() {
                ServerMessage::Response(response) => assert_eq!(
                    response.id(),
                    id as u64,
                    "each owing session must flush its own acknowledgement"
                ),
                other => panic!("expected a drained response, got {other:?}"),
            }
        }
        let _ = served.join();
    }

    /// Codex PR review finding 11 (P2): only a definitive stale-socket
    /// signal (ECONNREFUSED) may authorize unlinking the socket file. Any
    /// other connect failure (descriptor exhaustion, EACCES, ...) is
    /// inconclusive: unlinking then leaves a live daemon unreachable while
    /// another instance binds the same path.
    #[test]
    fn only_connection_refused_authorizes_unlinking_a_stale_socket() {
        use std::os::unix::fs::PermissionsExt;

        // A stale socket (listener dropped, file left behind) is removable.
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("stale.sock");
        let listener = std::os::unix::net::UnixListener::bind(&stale).unwrap();
        drop(listener);
        assert!(authorizes_unlink(&connect_error(&stale)));

        // An inconclusive failure (EACCES with the parent dir closed to us;
        // meaningful only for non-root test users) must NOT authorize it.
        if !nix::unistd::getuid().is_root() {
            let closed = dir.path().join("closed");
            std::fs::create_dir(&closed).unwrap();
            let socket = closed.join("s.sock");
            let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
            let verdict = authorizes_unlink(&connect_error(&socket));
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
            drop(listener);
            assert!(
                !verdict,
                "EACCES is inconclusive and must abort startup, not unlink"
            );
        }
    }

    /// End-to-end bind behavior for the two clear outcomes.
    #[test]
    fn bind_refuses_live_and_replaces_stale_sockets() {
        let dir = tempfile::tempdir().unwrap();
        // Stale: listener gone, file remains.
        let stale_dir = dir.path().join("a");
        std::fs::create_dir(&stale_dir).unwrap();
        drop(std::os::unix::net::UnixListener::bind(stale_dir.join("s.sock")).unwrap());
        assert!(IpcServer::bind(&stale_dir, "s.sock").is_ok());
        // Live: a serving listener owns the path.
        let live_dir = dir.path().join("b");
        std::fs::create_dir(&live_dir).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(live_dir.join("s.sock")).unwrap();
        let err = IpcServer::bind(&live_dir, "s.sock")
            .map(|_| ())
            .expect_err("live socket must abort bind");
        assert!(
            err.to_string().contains("another daemon"),
            "live socket must abort bind, got: {err}"
        );
        drop(listener);
    }

    fn connect_error(path: &Path) -> io::Error {
        UnixStream::connect(path).expect_err("connect against a socket file must fail or succeed")
    }

    /// Shrinks a stream's `SO_RCVBUF` (std exposes no UnixStream helper) so
    /// a frame a few hundred KiB long cannot fit without the peer reading —
    /// host-independent blocking regardless of kernel buffer defaults.
    fn set_rcvbuf(stream: &UnixStream, bytes: usize) {
        nix::sys::socket::setsockopt(stream, nix::sys::socket::sockopt::RcvBuf, &bytes)
            .expect("SO_RCVBUF applies");
    }
}
