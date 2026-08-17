//! Daemon-side IPC server: bind, authenticate, dispatch, fan out events.
//!
//! The module family: this module owns the server itself — the accept
//! loop, its timing budgets (`ServeBudgets`), and the session-worker
//! bookkeeping; `bind` owns the socket-bind path (entry guards,
//! stale-socket policy, the root-gated group hand-off); `session`
//! owns one accepted connection (handshake, dispatch loop, writer
//! thread, teardown ordering).

use std::io;
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use protonwire_frontend_api::{ClientInfo, Request, RequestResult, RpcError};
use tracing::{debug, warn};

use crate::bus::EventBus;
use crate::peer::PeerCredentials;

mod bind;
mod session;

use crate::server::session::handle_session;

/// Interval at which session loops wake to check the stop flag while blocked
/// on reads.
const READ_POLL: Duration = Duration::from_millis(250);

/// A connection must complete the hello handshake within this window.
const HELLO_DEADLINE: Duration = Duration::from_secs(5);

/// Ceiling on any ONE message's write to one client (R7-1): enforced by a
/// userspace deadline watchdog in the writer thread (poll-for-writability
/// inside the remaining budget), with `SO_SNDTIMEO` kept only as a
/// syscall-level backstop. The measured record (sec round-7 probe; the
/// round-5 instrumented run in docs/review-log.md's SO_SNDTIMEO track
/// item): `SO_SNDTIMEO` bounds each WAIT, not the message — progress
/// resets it, and a multi-syscall write multiplies it (a 0.9 MiB frame
/// is ~4 syscalls) — and under steady drain it never expires (80+ s
/// watched under a 1 s timeout). A peer that stops reading (or dribbles)
/// loses its session instead of pinning a writer thread — and a reserved
/// slot — forever.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall ceiling on post-stop draining. `SO_SNDTIMEO` bounds each WRITE
/// syscall, not the shutdown join: a session that keeps dribbling reads (or
/// a handler that blocks) would otherwise hold `serve()` open indefinitely.
/// Three write ceilings: one blocked final write, one slow poll loop, and
/// one in-flight dispatch each get a full chance to finish.
const DRAIN_CEILING: Duration = WRITE_TIMEOUT.saturating_mul(3);

/// R9-2 (round 9, P1): the per-session request-credit window — the
/// dispatcher stops READING new requests while this many writer-channel
/// messages remain unwritten.
///
/// The finding: `writer_tx` (`sync_channel(256)`, shared by responses and
/// events) let a pipelining authorized client park ~230 MiB per session
/// (~14 GiB across `MAX_SESSIONS` = 64) by stalling its reader. The
/// dispatcher's blocking `send` was backpressure on the dispatch THREAD,
/// never a bound on parked BYTES — and the R7-1 per-message write
/// watchdog only ends one already-stuck write; it does nothing about the
/// queue parked behind it.
///
/// Bound (by construction, approximate and deliberately conservative):
/// every channel slot holds one typed `ServerMessage` whose heap is
/// dominated by its payload strings, each bounded by the codec's
/// [`crate::frame::MAX_FRAME_LEN`] payload check (wire shape: a 4-byte
/// prefix plus a <=1 MiB payload per frame). Worst case parked per
/// session is therefore ~(window + 1 mid-write + 1 mid-dispatch) x ~1 MiB
/// ~= 18 MiB, against ~230 MiB for the full-channel pre-fix shape — and
/// a burst past the window WAITS rather than buffers, so a hostile
/// client just experiences flow control. No termination semantics.
///
/// Treatment of the other traffic on the same channel:
/// - EVENTS never wait on the window (only the dispatcher does). They
///   are daemon-authored, not client-amplifiable, and are bounded
///   upstream by the bus's own 256-slot drop-and-resync queue (X4). They
///   do COUNT toward it, deliberately: a session whose events are not
///   draining should not read more of its client's requests either.
/// - The hello ack and the X4 resync marker each occupy one slot of the
///   same window; neither can wedge it — the marker is only sent after a
///   successful event forward, and the ack precedes the first request
///   read (the hello gate, WO-5, is an ORDERing device and composes: the
///   ack is queued, the gate opens, and only then can any request
///   consume window slots).
const MAX_UNWRITTEN_MESSAGES: usize = 16;

/// How often a dispatcher parked on the R9-2 window re-checks it. Small
/// so a reopened window costs one poll of pipelining latency, not a
/// read-timeout quantum.
const WRITE_WINDOW_POLL: Duration = Duration::from_millis(10);

/// Timing budgets for one `serve()` invocation. Production uses the
/// defaults; tests inject shrunk values so drain, dribble, and
/// stalled-writer scenarios run in milliseconds instead of wall-clock
/// seconds (QA robustness round 3; R7-1 adds the write ceiling).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServeBudgets {
    /// Window in which a connection must complete the hello handshake.
    pub(crate) hello_deadline: Duration,
    /// Overall ceiling on draining sessions after the stop flag is set.
    pub(crate) drain_ceiling: Duration,
    /// Ceiling on any ONE message's write to a client that has stopped
    /// reading (R7-1): each writer-thread write is deadline-bounded in
    /// userspace, because `SO_SNDTIMEO` bounds each WAIT, not the
    /// message — progress resets it, a multi-syscall write multiplies
    /// it, and under steady drain it never expires at all (sec round-7
    /// probe).
    pub(crate) write_timeout: Duration,
}

impl Default for ServeBudgets {
    fn default() -> Self {
        Self {
            hello_deadline: HELLO_DEADLINE,
            drain_ceiling: DRAIN_CEILING,
            write_timeout: WRITE_TIMEOUT,
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
    /// WRITE_TIMEOUT ceiling. The server enforces an overall
    /// DRAIN_CEILING on shutdown draining: a handler still running past
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
    /// The bound socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Accepts and serves sessions until `stop` is set, then returns.
    ///
    /// Each session runs on two threads (reader/dispatcher and writer) and is
    /// fully isolated: a misbehaving client only drops its own session.
    /// Sessions are bounded (64), must complete the handshake within 5 s,
    /// cannot pin a writer past 10 s per message (a userspace write
    /// deadline, R7-1 — not just `SO_SNDTIMEO`), and cannot park more than
    /// `MAX_UNWRITTEN_MESSAGES` (16) unwritten output messages per session
    /// (R9-2: the dispatcher pauses request reads at the window, so a
    /// pipelining client that stalls its reader waits instead of parking
    /// ~230 MiB of responses in the writer channel).
    ///
    /// Returning implies every session has drained or been given up on —
    /// the flush of stop-time responses is an ATTEMPT, not a delivery
    /// guarantee (Codex PR review round 2, finding 4). Each message
    /// queued before the stop flag — an administrator Shutdown
    /// acknowledgement, for example — gets one write_timeout of
    /// deadline-bounded writing (R7-1): a peer draining at
    /// frame-size / write_timeout pace receives it in full, while a peer
    /// that is momentarily not reading — a TUI mid-refresh, the named
    /// casualty — receives a truncated frame followed by a clean
    /// mid-frame EOF (the writer's deadline expiry breaks the loop and
    /// shuts the shared socket down). DRAIN_CEILING (3× the 10 s write
    /// ceiling) bounds only the shutdown JOIN/DETACH, not per-message
    /// delivery: a session still owing work past it has its socket forced
    /// down and its worker detached, because `SO_SNDTIMEO` bounds each
    /// write syscall — not the shutdown join — and a blocking handler
    /// (see [`RequestHandler::handle`]) would otherwise pin `serve()`
    /// indefinitely.
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
        self.serve_observed(handler, stop, budgets, &|_| {});
    }

    /// [`IpcServer::serve_with`] with an observer fired after EVERY
    /// accept-loop reap (tests watch ended workers leave the list without
    /// waiting for shutdown; production passes a no-op).
    pub(crate) fn serve_observed<H: RequestHandler + 'static>(
        &self,
        handler: Arc<H>,
        stop: Arc<AtomicBool>,
        budgets: ServeBudgets,
        observe: &dyn Fn(ReapStats),
    ) {
        // Rust-review round 7 (drain/write ordering): DRAIN_CEILING derives
        // from the const while the writer threads use the INJECTED
        // write_timeout — nothing tied the two together for test budgets.
        // Pin the documented ordering (three write ceilings, per
        // DRAIN_CEILING's rationale) at every injection point so a
        // mis-shrunk budget fails loudly here instead of silently
        // violating the drain contract.
        debug_assert!(
            budgets.drain_ceiling >= budgets.write_timeout.saturating_mul(3),
            "drain_ceiling must cover >= 3x write_timeout (one blocked final \
             write, one slow poll loop, one in-flight dispatch); got \
             drain_ceiling={:?}, write_timeout={:?}",
            budgets.drain_ceiling,
            budgets.write_timeout
        );
        // Poll-accept so shutdown is responsive without signal plumbing here.
        if let Err(e) = self.listener.set_nonblocking(true) {
            warn!("cannot switch accept loop to nonblocking mode: {e}");
            return;
        }
        let mut sessions: Vec<SessionWorker> = Vec::new();
        // Cumulative reaped count across the whole accept loop: the load-
        // bearing half of [`ReapStats`] — `remaining` alone cannot pin the
        // reap because it is trivially 0 before any client connects.
        let mut reaped = 0usize;
        while !stop.load(Ordering::SeqCst) {
            // Reap before (potentially) accepting again: the list only
            // grows otherwise, and a client that reconnects on a cadence
            // (the TUI retries every 750 ms) leaves one dead worker per
            // attempt — ~115k handles a day held until shutdown
            // (pr-champion WO-4).
            reaped += reap_finished(&mut sessions);
            observe(ReapStats {
                reaped,
                remaining: sessions.len(),
            });
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
                            handle_session(
                                stream,
                                handler,
                                stop,
                                budgets.hello_deadline,
                                budgets.write_timeout,
                            )
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
                let _ = session.join.join();
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

/// Snapshot of the accept loop's reap bookkeeping, reported through the
/// [`IpcServer::serve_observed`] seam after every reap pass.
///
/// `reaped` is CUMULATIVE across the whole `serve()` call — the load-
/// bearing field: `remaining == 0` is trivially true before any client has
/// ever connected, so only a monotonically growing reaped count can pin
/// that ended workers actually leave the list (pr-champion WO-R3).
///
/// The fields are read by the recording observers tests install through
/// the seam; production's observer is a no-op, so only the lib build sees
/// them constructed-but-unread.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReapStats {
    /// Workers reaped since the accept loop started (cumulative).
    pub(crate) reaped: usize,
    /// Workers still in the list after this reap pass.
    pub(crate) remaining: usize,
}

/// Joins and removes session workers whose threads have finished, and
/// returns how many left.
///
/// `serve_observed` pushes one [`SessionWorker`] per accepted connection
/// and calls this from the top of every accept-loop iteration, so the list
/// holds only the sessions still being served. Joining a handle whose
/// thread already reported [`std::thread::JoinHandle::is_finished`]
/// returns immediately, so this never blocks on a live session — and the
/// shutdown drain below is unaffected: a worker joined here is gone from
/// the list before the drain phase ever looks at it.
fn reap_finished(sessions: &mut Vec<SessionWorker>) -> usize {
    let mut index = 0;
    let mut reaped = 0;
    while index < sessions.len() {
        if sessions[index].join.is_finished() {
            let finished = sessions.remove(index);
            let _ = finished.join.join();
            reaped += 1;
        } else {
            index += 1;
        }
    }
    reaped
}

/// Fixtures shared by the `server` family's test modules (this module's
/// serve-loop tests, `bind`'s, and `session`'s): the null handler, the
/// hello helper, and the receive-buffer shrinker. Handlers that encode
/// test intent stay inside each test module, per `test_util`'s split.
#[cfg(test)]
pub(crate) mod test_support {
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;

    use protonwire_frontend_api::{
        ClientInfo, ClientMessage, ClientSurface, Request, RequestResult, RpcError, ServerMessage,
    };

    use crate::bus::EventBus;
    use crate::frame::{read_msg, write_msg};
    use crate::server::{RequestHandler, SessionContext};

    pub(crate) struct NullHandler {
        pub(crate) version: String,
        pub(crate) bus: EventBus,
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

    pub(crate) fn info() -> ClientInfo {
        ClientInfo {
            name: "server-test".into(),
            version: "0".into(),
            surface: ClientSurface::Other,
        }
    }

    pub(crate) fn spawn_server(
        dir: &tempfile::TempDir,
        handler: Arc<NullHandler>,
    ) -> crate::test_util::TestServer {
        crate::test_util::TestServer::start(dir.path(), "server-test.sock", handler)
            .expect("test server binds")
    }

    pub(crate) fn connect_and_hello(path: &std::path::Path) -> std::os::unix::net::UnixStream {
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

    /// Shrinks a stream's `SO_RCVBUF` (std exposes no UnixStream helper) so
    /// a frame a few hundred KiB long cannot fit without the peer reading —
    /// host-independent blocking regardless of kernel buffer defaults.
    pub(crate) fn set_rcvbuf(stream: &UnixStream, bytes: usize) {
        nix::sys::socket::setsockopt(stream, nix::sys::socket::sockopt::RcvBuf, &bytes)
            .expect("SO_RCVBUF applies");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, mpsc};

    use protonwire_frontend_api::{ClientMessage, Request, ServerMessage};

    use super::test_support::{NullHandler, connect_and_hello, info, set_rcvbuf, spawn_server};
    use super::*;
    use crate::bus::MAX_SESSIONS;
    use crate::frame::{read_msg, write_msg};

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
    ///
    /// Round 7 re-shape (honest straggler class): R7-1's watchdog bounds a
    /// pinned WRITER inside write_timeout, and the round-7 invariant
    /// (drain_ceiling >= 3x write_timeout, asserted in serve_observed)
    /// keeps that strictly below the ceiling — so a pinned writer can no
    /// longer outlive the drain, and the straggler that exercises the
    /// force-down path is a BLOCKING DISPATCH: the handler below sets the
    /// stop flag, then sleeps past the whole drain window before answering
    /// a huge pong. (The pre-R7-1 shape — a pinned writer outlasting the
    /// join — is covered by the two watchdog tests above, which pin the
    /// writer's own deadline instead.)
    #[test]
    fn serve_returns_within_the_drain_ceiling_when_a_dispatch_blocks_past_it() {
        use std::time::{Duration, Instant};

        /// Sets the stop flag, then stays inside handle() past the drain
        /// window before answering with a pong far larger than the socket
        /// buffers of a client that never reads.
        struct StopThenBlockedHugePong {
            bus: Arc<EventBus>,
            stop: Arc<AtomicBool>,
        }
        impl RequestHandler for StopThenBlockedHugePong {
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
                        // Past the drain deadline even in the worst case:
                        // the accept loop observes the flag within one
                        // READ_POLL (250 ms) and the ceiling adds 600 ms,
                        // so the straggler must still be mid-handle at
                        // ~850 ms.
                        std::thread::sleep(Duration::from_millis(1200));
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
        let handler = Arc::new(StopThenBlockedHugePong {
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
                    // Satisfies the round-7 invariant: 3 x 150 ms <= 600 ms.
                    write_timeout: Duration::from_millis(150),
                    ..ServeBudgets::default()
                },
            )
        });

        // Handshake normally, then shrink our receive buffer and never read
        // again: the eventual ~0.86 MiB pong cannot fit the socket buffers.
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

        // Pre-fix, serve() waited out every session to completion (forever
        // for a blocked handler); the bound must be the injected drain
        // ceiling plus polling slack.
        let started = Instant::now();
        while !served.is_finished() {
            assert!(
                Instant::now() < started + ceiling + Duration::from_secs(2),
                "serve() is pinned past the drain ceiling by a blocked dispatch"
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

    /// pr-champion WO-4: `serve_with` pushed a `SessionWorker` per accepted
    /// connection and nothing ever shrank the list until shutdown. A client
    /// that reconnects on a cadence (the TUI retries every 750 ms) leaves
    /// one dead `JoinHandle` plus weak stream pointer per connection —
    /// roughly 115k/day of handle bookkeeping held for the daemon's whole
    /// lifetime. The accept loop must reap finished workers as it goes,
    /// while the shutdown drain semantics stay unchanged (only finished
    /// workers leave; the ceiling phase never sees one it already joined).
    #[test]
    fn reap_finished_joins_and_removes_ended_workers() {
        let mut sessions: Vec<SessionWorker> = Vec::new();
        // One still-serving worker whose handle must survive the reap.
        let live_done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&live_done);
        sessions.push(SessionWorker {
            join: std::thread::spawn(move || {
                while !flag.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }),
            stream: std::sync::Weak::new(),
        });
        // N short-lived workers holding weak handles on streams that are
        // already gone (Weak::new()), like sessions the drain phase will
        // never need to force down.
        for _ in 0..8 {
            sessions.push(SessionWorker {
                join: std::thread::spawn(|| ()),
                stream: std::sync::Weak::new(),
            });
        }
        // Let every short-lived worker finish; the live one must not.
        let deadline = Instant::now() + Duration::from_secs(10);
        while sessions.iter().filter(|s| !s.join.is_finished()).count() > 1 {
            assert!(
                Instant::now() < deadline,
                "short-lived workers never finished"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            reap_finished(&mut sessions),
            8,
            "the reap must report every ended worker it removed"
        );
        assert_eq!(
            sessions.len(),
            1,
            "the reap must keep the worker that is still serving"
        );
        assert!(!sessions[0].join.is_finished());
        // Once the live worker ends, the next reap empties the list.
        live_done.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !sessions[0].join.is_finished() {
            assert!(Instant::now() < deadline, "live worker never finished");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            reap_finished(&mut sessions),
            1,
            "the reap must report the last worker too"
        );
        assert!(
            sessions.is_empty(),
            "the reap must join and remove every ended worker"
        );
    }

    /// pr-champion WO-R3 mutation gap: deleting the accept loop's
    /// `reap_finished` call passed the ENTIRE suite (only -D warnings
    /// caught the full removal; partial wiring mutations slipped
    /// silently). The observer seam makes the reap directly observable:
    /// `serve_observed` reports a cumulative [`ReapStats`] after every
    /// accept-loop reap, and three ended clients must drive `reaped` to
    /// three — a deleted (or mis-wired) reap call leaves it stuck at 0
    /// forever, which the watchdog below turns into a fast failure.
    #[test]
    fn accept_loop_reaps_ended_workers() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = IpcServer::bind(dir.path(), "reap.sock").unwrap();
        let path = server.socket_path().to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let stats: Arc<Mutex<Vec<ReapStats>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&stats);
        let observe = move |snapshot: ReapStats| {
            recorder.lock().unwrap().push(snapshot);
        };
        let stop_flag = Arc::clone(&stop);
        let served = std::thread::spawn(move || {
            server.serve_observed(handler, stop_flag, ServeBudgets::default(), &observe)
        });

        for _ in 0..3 {
            drop(connect_and_hello(&path));
        }

        // Watchdog: every dropped client's worker must be reaped by the
        // accept loop WHILE THE SERVER KEEPS RUNNING — not parked in the
        // list until shutdown. Cumulative `reaped` reaching 3 is the pin;
        // `remaining` alone could not carry it (it is 0 before any client
        // ever connects).
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let reaped = stats
                .lock()
                .unwrap()
                .last()
                .map(|snapshot| snapshot.reaped)
                .unwrap_or(0);
            if reaped >= 3 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the accept loop never reaped the ended workers: cumulative \
                 reaped is stuck at {reaped} after 3 clients connected and \
                 disconnected — the reap call is gone or mis-wired"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        // Each snapshot reported a consistent list: cumulative reaped
        // never exceeds the number of sessions the loop ever pushed
        // (3), and remaining never exceeds it either.
        for snapshot in stats.lock().unwrap().iter() {
            assert!(snapshot.reaped <= 3, "impossible reap count: {snapshot:?}");
            assert!(
                snapshot.remaining <= 3,
                "impossible remainder: {snapshot:?}"
            );
        }

        stop.store(true, Ordering::SeqCst);
        let _ = served.join();
    }
}
