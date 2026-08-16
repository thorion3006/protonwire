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
const DRAIN_CEILING: Duration = WRITE_TIMEOUT.saturating_mul(3);

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
    /// Binds `socket_dir/socket_name`.
    ///
    /// Creates the directory if missing, refuses to displace a live daemon's
    /// socket, removes a stale socket file left by an unclean shutdown, and
    /// refuses loudly to remove any NON-socket entry at the path (a regular
    /// file there also answers ECONNREFUSED on the liveness probe — the
    /// probe alone must never authorize the unlink). The socket is created
    /// with mode `0o660`. See
    /// [`IpcServer::bind_with_group`] for the client-group chown a root
    /// daemon needs on top of that mode.
    pub fn bind(socket_dir: &Path, socket_name: &str) -> io::Result<Self> {
        Self::bind_with_group(socket_dir, socket_name, None)
    }

    /// [`IpcServer::bind`] with the socket additionally chowned to `group`.
    ///
    /// PRD 6.3: a root daemon creates the socket root:root, and the 0o660
    /// mode alone then admits no unprivileged client. With a group
    /// configured the socket is chowned to that group's gid (owner
    /// untouched) right after the mode is applied, so members of the group
    /// can connect. An unresolvable group name fails loudly — a daemon
    /// started with a typo'd group is a daemon nobody can reach.
    pub fn bind_with_group(
        socket_dir: &Path,
        socket_name: &str,
        group: Option<&str>,
    ) -> io::Result<Self> {
        Self::bind_with_resolved(
            socket_dir,
            socket_name,
            group,
            &resolve_group_gid,
            &chown_socket_group,
        )
    }

    /// The bind path with BOTH the group resolver and the chown injectable
    /// (tests pin the hand-off between them — resolver output to chown
    /// input, exactly once, with the bound path — without a group database
    /// or root; production goes through [`IpcServer::bind_with_group`]).
    fn bind_with_resolved(
        socket_dir: &Path,
        socket_name: &str,
        group: Option<&str>,
        resolver: &dyn Fn(&str) -> io::Result<Option<nix::unistd::Gid>>,
        chown: &dyn Fn(&Path, &str, nix::unistd::Gid) -> io::Result<()>,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(socket_dir)?;
        let socket_path = socket_dir.join(socket_name);
        if socket_path.exists() {
            refuse_unless_stale_socket(&socket_path)?;
            std::fs::remove_file(&socket_path)?;
        }
        let listener = UnixListener::bind(&socket_path)?;
        set_socket_mode(&socket_path)?;
        if let Some(name) = group {
            let gid = resolver(name)?
                .ok_or_else(|| io::Error::other(format!("socket group `{name}` does not exist")))?;
            chown(&socket_path, name, gid)?;
        }
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
    /// bounded overall by DRAIN_CEILING (3× the 10 s write ceiling):
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

/// Authorizes removing the entry at `socket_path` only if it is a SOCKET
/// that no live daemon is serving (pr-champion round 6, WO-W1).
///
/// The liveness probe alone cannot carry this: connect(2) to ANY non-socket
/// path — a regular file above all — answers ECONNREFUSED, the exact signal
/// [`authorizes_unlink`] treats as proof of staleness. Ungated, that let
/// bind remove the user's file and bind over the crater. The entry's TYPE
/// is therefore checked first (and the probe never even runs against a
/// non-socket), and any non-socket entry aborts bind loudly, naming the
/// path and what it actually is.
fn refuse_unless_stale_socket(socket_path: &Path) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let meta = std::fs::metadata(socket_path)?;
    if meta.file_type().is_socket() {
        return ensure_not_live(socket_path);
    }
    Err(io::Error::other(format!(
        "refusing to remove {}: not a socket ({})",
        socket_path.display(),
        entry_kind(&meta)
    )))
}

/// Human name for an entry's file type, used to say WHAT bind refused to
/// remove (metadata follows symlinks, so a link is reported as whatever it
/// targets — the link itself is still never unlinked).
fn entry_kind(meta: &std::fs::Metadata) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    let file_type = meta.file_type();
    if file_type.is_file() {
        "regular file"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_fifo() {
        "FIFO"
    } else if file_type.is_char_device() {
        "character device"
    } else if file_type.is_block_device() {
        "block device"
    } else {
        "unknown entry type"
    }
}

fn set_socket_mode(socket_path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))
}

/// Resolves a group name to its gid through the system group database.
fn resolve_group_gid(name: &str) -> io::Result<Option<nix::unistd::Gid>> {
    nix::unistd::Group::from_name(name)
        .map(|group| group.map(|g| g.gid))
        .map_err(|e| io::Error::other(format!("cannot look up group `{name}`: {e}")))
}

/// Chowns the bound socket to `gid`, leaving its owner alone.
fn chown_socket_group(socket_path: &Path, name: &str, gid: nix::unistd::Gid) -> io::Result<()> {
    nix::unistd::chown(socket_path, None, Some(gid))
        .map_err(|e| io::Error::other(format!("cannot chown socket to group `{name}`: {e}")))
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
        // A dead writer takes the session with it (Codex round 5, P1):
        // every clone shares ONE socket, so shutting it down here also
        // fails the dispatcher's read half and drives `serve_messages`
        // through the normal teardown (unsubscribe + slot release).
        // Without this, a client that triggers the write ceiling with an
        // oversized response and then merely holds its side open keeps
        // its reserved session slot forever — 64 such connections wedge
        // the daemon at MAX_SESSIONS. On normal teardown the socket is
        // already closing, so the extra shutdown is a no-op there.
        let _ = write_stream.shutdown(Shutdown::Both);
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
    // pr-champion WO-5: the forwarder is gated so nothing it holds can
    // reach the wire before the hello ack. Subscribe() happens before the
    // handshake on purpose (events published mid-handshake must not be
    // lost), but unguarded the forwarder raced them onto the socket ahead
    // of HelloAck — and a client rejects any non-ack frame while
    // handshaking. The gate opens only after the ack is queued; a session
    // that ends pre-hello drops `gate_tx`, which unblocks (and ends) the
    // forwarder instead of stranding it on the closed gate.
    let (gate_tx, gate_rx) = mpsc::sync_channel::<()>(1);
    let event_forward = {
        let forward_tx = writer_tx.clone();
        std::thread::spawn(move || {
            if gate_rx.recv().is_err() {
                return; // session ended before hello; nothing to forward
            }
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
        gate_tx,
        &handler,
        &peer,
        &stop,
        hello_deadline,
    );
    // Teardown order is load-bearing: dropping our sender alone is not
    // enough — the forwarder holds a clone — so we must unsubscribe BEFORE
    // joining. Unsubscribe closes the bus sender, which ends the forwarder,
    // which drops the last writer-sender clone, which ends the writer.
    // `gate_tx` is already gone by then: serve_messages took it by value,
    // so every one of its exit paths (including pre-hello refusals and
    // read errors) dropped it and unblocked the forwarder first. Joining
    // first deadlocks and leaks the session slot plus both threads
    // (rust-review finding 1).
    drop(writer_tx);
    drop(_guard);
    let _ = writer.join();
    let _ = event_forward.join();
    debug!(uid = peer.uid, outcome = ?result, "session closed");
}

/// Handshake + request loop for one session.
///
/// `gate_tx` opens the event gate the forwarder blocks on: it is sent ONE
/// `()` immediately after the hello ack is queued — the writer channel is
/// FIFO, so the ack reaches the wire before any forwarded event — and it is
/// dropped on every exit path, which ends a forwarder still waiting on the
/// gate (a session that never handshook).
fn serve_messages(
    read_half: &mut UnixStream,
    writer_tx: &mpsc::SyncSender<ServerMessage>,
    gate_tx: mpsc::SyncSender<()>,
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
                // The ack is queued ahead of anything the gated forwarder
                // holds, and the writer drains its channel in FIFO order —
                // so the ack is the first frame the client reads. Open the
                // gate; buffered pre-hello events follow the ack onto the
                // wire instead of beating it (pr-champion WO-5).
                let _ = gate_tx.send(());
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

    use std::sync::{Arc, Mutex};
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

    /// pr-champion round 6, WO-W1: a REGULAR file at the socket path also
    /// answers ECONNREFUSED on the liveness probe (connect(2) to any
    /// non-socket refuses), so `authorizes_unlink` alone passed and
    /// `remove_file` destroyed the user's file before binding over it. The
    /// entry's TYPE must authorize the unlink: anything but a socket aborts
    /// bind loudly, naming the path and the actual entry type, and the
    /// file's contents survive untouched. A stale SOCKET keeps the existing
    /// replace-and-bind behavior.
    #[test]
    fn bind_refuses_to_unlink_non_socket_entries() {
        let dir = tempfile::tempdir().unwrap();

        // A regular file at the bind path: refuse loudly, name the type,
        // leave the contents intact.
        let file_dir = dir.path().join("regular");
        std::fs::create_dir(&file_dir).unwrap();
        let hoarded = file_dir.join("s.sock");
        std::fs::write(&hoarded, "precious data").unwrap();
        let err = IpcServer::bind(&file_dir, "s.sock")
            .map(|_| ())
            .expect_err("a regular file at the bind path must abort bind");
        assert!(
            err.to_string().contains("refusing to remove"),
            "the refusal must be explicit, got: {err}"
        );
        assert!(
            err.to_string().contains("regular file"),
            "the refusal must name the entry type, got: {err}"
        );
        assert!(
            err.to_string().contains("s.sock"),
            "the refusal must name the path, got: {err}"
        );
        assert!(
            hoarded.is_file(),
            "the entry itself must survive the refusal"
        );
        assert_eq!(
            std::fs::read_to_string(&hoarded).unwrap(),
            "precious data",
            "bind must not destroy the file's contents"
        );

        // A directory at the bind path: refused too (remove_file on a
        // directory only fails with EISDIR — an opaque error that names
        // neither the refusal nor the type).
        let dir_case = dir.path().join("dircase");
        std::fs::create_dir(&dir_case).unwrap();
        let as_socket = dir_case.join("s.sock");
        std::fs::create_dir(&as_socket).unwrap();
        let err = IpcServer::bind(&dir_case, "s.sock")
            .map(|_| ())
            .expect_err("a directory at the bind path must abort bind");
        assert!(
            err.to_string().contains("refusing to remove"),
            "directories are refused like any non-socket, got: {err}"
        );
        assert!(
            err.to_string().contains("directory"),
            "the refusal must name the entry type, got: {err}"
        );
        assert!(as_socket.is_dir(), "the directory must survive");

        // A stale socket (listener dropped, file left behind) is still
        // replaced and bound — existing behavior pinned.
        let stale_dir = dir.path().join("stale");
        std::fs::create_dir(&stale_dir).unwrap();
        drop(std::os::unix::net::UnixListener::bind(stale_dir.join("s.sock")).unwrap());
        let server = IpcServer::bind(&stale_dir, "s.sock")
            .expect("a stale socket at the bind path is still replaced");
        assert!(
            server.socket_path().exists(),
            "the replacement socket must be bound"
        );
    }

    /// pr-champion WO-7 (PRD 6.3): bind() chmods the socket 0o660 but
    /// never chgrps it, so a root daemon leaves the socket root:root and
    /// every unprivileged client eats EACCES. `bind_with_group` must
    /// chown to the configured group's gid — and an unresolvable name
    /// must fail loudly rather than start a daemon nobody can reach.
    #[test]
    fn bind_with_group_fails_loud_on_an_unknown_group() {
        let dir = tempfile::tempdir().unwrap();
        let err = IpcServer::bind_with_group(
            dir.path(),
            "nope.sock",
            Some("protonwire-no-such-group-3f9a"),
        )
        .map(|_| ())
        .expect_err("an unresolvable group must abort bind");
        assert!(
            err.to_string().contains("does not exist"),
            "fail-loud error must name the problem, got: {err}"
        );
    }

    /// A resolver failure (group database unreadable, say) maps to an
    /// io::Error instead of a panic or a silent skip.
    #[test]
    fn bind_with_group_maps_resolver_failures() {
        let dir = tempfile::tempdir().unwrap();
        let err = IpcServer::bind_with_resolved(
            dir.path(),
            "boom.sock",
            Some("clients"),
            &|_name| Err(io::Error::other("group database on fire")),
            &|_path, _name, _gid| panic!("resolution failed first: the chown must not run"),
        )
        .map(|_| ())
        .expect_err("a resolver failure must abort bind");
        assert!(
            err.to_string().contains("group database on fire"),
            "got: {err}"
        );
    }

    /// The second group-lookup error text (alongside the resolver-Err test
    /// above): a name that resolves to nothing must fail loudly naming the
    /// group — a daemon started with a typo'd group is a daemon nobody can
    /// reach.
    #[test]
    fn unresolved_group_names_fail_loud_through_the_seam() {
        let dir = tempfile::tempdir().unwrap();
        let err = IpcServer::bind_with_resolved(
            dir.path(),
            "missing.sock",
            Some("wheel-clients"),
            &|_name| Ok(None),
            &|_path, _name, _gid| panic!("no gid was resolved: the chown must not run"),
        )
        .map(|_| ())
        .expect_err("an unresolvable group must abort bind");
        assert!(
            err.to_string().contains("does not exist"),
            "the lookup-failure text must say so, got: {err}"
        );
        assert!(
            err.to_string().contains("wheel-clients"),
            "the lookup-failure text must name the group, got: {err}"
        );
    }

    /// Without a configured group nothing is resolved or chowned: the
    /// socket keeps the process group and the 0o660 mode.
    #[test]
    fn bind_without_a_group_never_resolves_or_chowns() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let server = IpcServer::bind_with_resolved(
            dir.path(),
            "plain.sock",
            None,
            &|_| panic!("no group configured: the resolver must not run"),
            &|_path, _name, _gid| panic!("no group configured: the chown must not run"),
        )
        .unwrap();
        let meta = std::fs::metadata(server.socket_path()).unwrap();
        assert_eq!(meta.gid(), nix::unistd::getgid().as_raw());
        assert_eq!(meta.mode() & 0o777, 0o660);
    }

    /// The effectiveness pin for the chown (qa mutation gap): the chown
    /// seam must fire EXACTLY ONCE per configured group, with the bound
    /// socket's path, the configured group name, and the gid the RESOLVER
    /// returned — the hand-off `bind_with_group` exists to perform. The
    /// old `bind_with_group_applies_the_resolved_gid` pin was tautological
    /// (a fresh socket's gid already equals the process egid, so its
    /// asserts held with the chown call deleted); recording the chown's
    /// arguments makes the delete-chown mutation fail here.
    #[test]
    fn chown_seam_receives_the_resolved_gid() {
        // (Mutex comes from the module-level `use std::sync::{Arc, Mutex};`
        // — the local re-import shadowed it; rust-review nit.)
        let dir = tempfile::tempdir().unwrap();
        let calls: Mutex<Vec<(PathBuf, String, u32)>> = Mutex::new(Vec::new());
        let server = IpcServer::bind_with_resolved(
            dir.path(),
            "seam.sock",
            Some("wheel-clients"),
            // A gid this process does NOT hold: the seam runs unprivileged
            // precisely because the real chown never happens.
            &|_name| Ok(Some(nix::unistd::Gid::from_raw(12345))),
            &|path, name, gid| {
                calls
                    .lock()
                    .unwrap()
                    .push((path.to_owned(), name.to_owned(), gid.as_raw()));
                Ok(())
            },
        )
        .unwrap();
        let recorded = calls.lock().unwrap();
        assert_eq!(
            recorded.len(),
            1,
            "the chown seam must be invoked exactly once for the configured group"
        );
        let (path, name, gid) = &recorded[0];
        assert_eq!(
            path,
            server.socket_path(),
            "the chown must target the bound socket"
        );
        assert_eq!(name, "wheel-clients");
        assert_eq!(*gid, 12345, "the chown must receive the resolver's gid");
    }

    /// A chown failure (EPERM, say) passes through and aborts bind with
    /// the group still named — never swallowed into a daemon nobody can
    /// reach.
    #[test]
    fn chown_failures_pass_through_and_name_the_group() {
        let dir = tempfile::tempdir().unwrap();
        let err = IpcServer::bind_with_resolved(
            dir.path(),
            "chown-boom.sock",
            Some("wheel-clients"),
            &|_name| Ok(Some(nix::unistd::Gid::from_raw(12345))),
            &|_path, name, _gid| {
                Err(io::Error::other(format!(
                    "cannot chown socket to group `{name}`: permission denied"
                )))
            },
        )
        .map(|_| ())
        .expect_err("a chown failure must abort bind");
        assert!(
            err.to_string().contains("wheel-clients"),
            "the chown error must pass through naming the group, got: {err}"
        );
        assert!(
            err.to_string().contains("permission denied"),
            "the chown error must survive propagation un-mangled, got: {err}"
        );
    }

    /// Real-syscall smoke test for the unprivileged chgrp path: POSIX lets
    /// any user chgrp a file it owns to a group it belongs to, so
    /// resolving to the process's own gid exercises the real chown(2)
    /// alongside the 0o660 mode.
    ///
    /// Honest scope: this does NOT pin the chown call — a fresh socket's
    /// gid already equals the process egid, so these asserts stay green
    /// with the chown deleted (qa mutation evidence). The effectiveness
    /// pin is [`chown_seam_receives_the_resolved_gid`]; this test still
    /// proves the real syscall succeeds where POSIX allows it unprivileged
    /// and leaves the mode intact. (Environments inside a restricted user
    /// namespace where supplementary gids are unmapped still admit the
    /// primary gid; a FOREIGN group is the root-gated test below.)
    #[test]
    fn bind_with_group_applies_the_resolved_gid() {
        use std::os::unix::fs::MetadataExt;

        let gid = nix::unistd::getgid();
        let dir = tempfile::tempdir().unwrap();
        let server = IpcServer::bind_with_resolved(
            dir.path(),
            "grouped.sock",
            Some("clients"),
            &|_| Ok(Some(gid)),
            &chown_socket_group,
        )
        .unwrap();
        let meta = std::fs::metadata(server.socket_path()).unwrap();
        assert_eq!(meta.gid(), gid.as_raw());
        assert_eq!(meta.mode() & 0o777, 0o660);
    }

    /// Root-gated integration (mirroring the root-gated arm of
    /// `only_connection_refused_authorizes_unlinking_a_stale_socket`):
    /// only root may chown to a group it does not belong to, so the full
    /// production path — real resolver against the group database, real
    /// chown — runs when the suite executes as root outside a user
    /// namespace. Inside a user namespace (/proc/self/ns/user differing
    /// from /proc/1/ns/user — or pid 1's file being unstatable, the form
    /// this host exhibits) the process holds no mapping for foreign gids
    /// and chown(2) to them answers EINVAL, so that environment skips
    /// with a NOTICE rather than failing on the kernel's terms.
    #[test]
    fn bind_with_group_chowns_to_a_real_group_when_root() {
        use std::os::unix::fs::MetadataExt;

        // Skip-FIRST: non-root before the user-namespace gate (rust-review
        // keep-id repro). Under `unshare --user --map-current-user --fork
        // --pid --mount-proc` the pid-namespace init shares our user
        // namespace, so in_a_user_namespace() sees identical namespace
        // links and answers false — gating on it first made a plain
        // non-root run fall through to a "the gate is broken" panic. The
        // foreign-group chown needs root regardless of namespaces, so a
        // non-root run simply skips. (A rootful-CI canary assert needs an
        // explicit env var — review-log track item, not built here.)
        if !nix::unistd::getuid().is_root() {
            eprintln!(
                "NOTICE: skipping bind_with_group_chowns_to_a_real_group_when_root: \
                 not running as root — the foreign-group chown arm needs root"
            );
            return;
        }
        if in_a_user_namespace() {
            eprintln!(
                "NOTICE: skipping bind_with_group_chowns_to_a_real_group_when_root: the \
                 suite runs in a user namespace (/proc/self/ns/user differs from \
                 /proc/1/ns/user) where chown to a foreign gid answers EINVAL"
            );
            return;
        }
        let group = nix::unistd::Group::from_name("nogroup")
            .expect("nogroup resolves")
            .expect("nogroup exists");
        let dir = tempfile::tempdir().unwrap();
        let server = IpcServer::bind_with_group(dir.path(), "clients.sock", Some("nogroup"))
            .expect("root binds with a real group");
        let meta = std::fs::metadata(server.socket_path()).unwrap();
        assert_eq!(
            meta.gid(),
            group.gid.as_raw(),
            "socket must be chowned to the configured group"
        );
        assert_eq!(meta.mode() & 0o777, 0o660);
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

    /// pr-champion WO-5: `subscribe()` and the forwarder spawn preceded the
    /// hello exchange, so an event published in that window reached the
    /// wire before `HelloAck` — and a client rejects anything but the ack
    /// while handshaking ("unexpected message during handshake",
    /// client.rs). The ack must be the first frame on the wire; the
    /// buffered event follows it.
    ///
    /// WO-R4 hardening, both directions:
    /// - GREEN-side regressions used to present as INFINITE HANGS (the
    ///   test stream had no read timeout), so the stream now carries a
    ///   5 s one and the ack's arrival is asserted punctual — a broken
    ///   gate fails fast instead of hanging the suite.
    /// - The red side used to rely on a 100 ms sleep heuristic. It is now
    ///   a DETERMINISTIC readability poll (nix::poll POLLIN, 750 ms)
    ///   between publishing the pre-hello event and sending Hello:
    ///   readable means an event frame is ALREADY on the wire pre-hello —
    ///   read it and fail reporting that frame; timeout means the gate
    ///   held it — proceed to Hello and assert ack-first (no sleep on
    ///   the green path).
    #[test]
    fn hello_ack_is_the_first_frame_even_under_pre_hello_events() {
        use nix::poll::{PollFd, PollFlags, poll as poll_fd};
        use protonwire_frontend_api::{Event, EventEnvelope, NoticeLevel};
        use std::os::fd::AsFd;

        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, Arc::clone(&handler));
        let mut stream = std::os::unix::net::UnixStream::connect(server.socket_path()).unwrap();
        // No-hang gate: every read below is bounded, so a regression that
        // stops the ack (or the follow-up event) surfaces as a fast TimedOut
        // failure rather than a suite-wide hang.
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Wait until the session has actually subscribed: the accept loop
        // polls at 250 ms, so a fixed sleep can race the subscribe and a
        // too-early publish would miss the session entirely.
        let deadline = Instant::now() + Duration::from_secs(10);
        while handler.event_bus().session_count() != 1 {
            assert!(Instant::now() < deadline, "session never subscribed");
            std::thread::sleep(Duration::from_millis(5));
        }

        // Publish BEFORE the hello, then poll the wire — deterministically,
        // not with a sleep. If the gate is broken the event is already on
        // the socket and POLLIN fires within the poll window; if the gate
        // held it, nothing is readable and the poll times out.
        handler
            .event_bus()
            .publish(ServerMessage::Event(EventEnvelope {
                seq: 1,
                event: Event::Notice {
                    level: NoticeLevel::Info,
                    message: "pre-hello".into(),
                },
            }));
        let mut fds = [PollFd::new(stream.as_fd(), PollFlags::POLLIN)];
        let readable = poll_fd(&mut fds, 750u16).unwrap() > 0
            && fds[0]
                .revents()
                .unwrap_or(PollFlags::empty())
                .contains(PollFlags::POLLIN);
        if readable {
            // Deterministic red: an event frame beat the handshake onto
            // the wire. Read and REPORT it instead of proceeding into a
            // misleading downstream assertion.
            let leaked: ServerMessage = read_msg(&mut stream).unwrap();
            match &leaked {
                ServerMessage::Event(_) => panic!(
                    "the event gate leaked: an event frame reached the wire \
                     before Hello — got {leaked:?}"
                ),
                // Any other frame (a HelloError, say) is a different
                // handshake defect, not an event-gate leak — say so
                // instead of misattributing it (rust-review Low).
                other => panic!(
                    "a non-event frame reached the wire before Hello — not an \
                     event-gate leak but a different handshake defect: got {other:?}"
                ),
            }
        }

        // The gate held the event: send Hello and demand the ack first,
        // promptly.
        let hello_sent_at = Instant::now();
        write_msg(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: 1,
                client: info(),
            },
        )
        .unwrap();
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloAck(_) => {}
            other => panic!("hello ack must be the first frame, got {other:?}"),
        }
        assert!(
            hello_sent_at.elapsed() < Duration::from_secs(5),
            "the ack must arrive punctually, took {} ms — a regression is \
             dragging the handshake",
            hello_sent_at.elapsed().as_millis()
        );
        // The buffered event is delivered right after the ack, not ahead
        // of it.
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::Event(envelope) => assert_eq!(envelope.seq, 1),
            other => panic!("expected the buffered event after the ack, got {other:?}"),
        }
    }

    fn connect_error(path: &Path) -> io::Error {
        UnixStream::connect(path).expect_err("connect against a socket file must fail or succeed")
    }

    /// Whether the test process runs in a DIFFERENT user namespace than
    /// init (pid 1). Namespace files live on nsfs, one stable inode per
    /// namespace, so equal (dev, ino) means the same namespace. A process
    /// in a user namespace typically cannot even stat pid 1's file (its
    /// owner is unmapped there — exactly this host's quirk), which is
    /// just as decisive: the real-chown arm may run only where the init
    /// user namespace is positively confirmed. In such namespaces the
    /// process holds no mapping for foreign gids and chown(2) to them
    /// answers EINVAL — not a code fault, so that environment skips with
    /// a NOTICE rather than failing on the kernel's terms.
    fn in_a_user_namespace() -> bool {
        use std::os::unix::fs::MetadataExt;

        match (
            std::fs::metadata("/proc/1/ns/user"),
            std::fs::metadata("/proc/self/ns/user"),
        ) {
            (Ok(init), Ok(current)) => (init.dev(), init.ino()) != (current.dev(), current.ino()),
            // Unstatable /proc (or absent pid 1) cannot confirm the init
            // user namespace; assume the guarded case.
            _ => true,
        }
    }

    /// Codex round 5 (P1): the writer thread exiting on a write timeout
    /// left the session alive — the dispatcher's read half (a try_clone of
    /// the SAME socket) kept polling unbounded post-hello, so a client that
    /// triggers the 10 s write ceiling with an oversized response and then
    /// holds its side open kept its reserved session slot forever; 64 such
    /// connections permanently wedged the daemon at MAX_SESSIONS. The
    /// writer must take the session with it: shutting the shared socket
    /// down fails the dispatcher's read and drives the normal teardown
    /// (unsubscribe + slot release).
    #[test]
    fn writer_failure_tears_down_the_session() {
        /// Answers pings with a 2 MiB pong — beyond MAX_FRAME_LEN, so the
        /// writer's write_msg fails the moment it dequeues the response.
        struct HugePong {
            bus: Arc<EventBus>,
        }
        impl RequestHandler for HugePong {
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
                    // Oversized ON PURPOSE: a response payload beyond
                    // MAX_FRAME_LEN makes write_msg fail inside the writer
                    // thread immediately — a writer failure with no
                    // dependence on host SO_SNDTIMEO behavior (see the
                    // comment at the trigger below).
                    Request::Ping { .. } => Ok(RequestResult::Pong {
                        nonce: "x".repeat(2 * crate::frame::MAX_FRAME_LEN),
                    }),
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
        let handler = Arc::new(HugePong {
            bus: Arc::new(EventBus::new()),
        });
        let server = IpcServer::bind(dir.path(), "writer-fail.sock").unwrap();
        let path = server.socket_path().to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let served = {
            let handler = Arc::clone(&handler);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || server.serve(handler, stop))
        };

        let mut stream = connect_and_hello(&path);
        // A tiny request (the oversized half is the RESPONSE): the server
        // dispatches it, the writer dequeues the 2 MiB pong, and write_msg
        // rejects it as TooLarge — a writer failure that fires on every
        // host. (The review finding's literal trigger — a blocked write
        // dying at the 10 s SO_SNDTIMEO ceiling — does NOT fire on this
        // kernel: instrumented runs show a blocked AF_UNIX send to a
        // 4 KiB peer buffer outlasting a 20 s window with a 10 s write
        // timeout set. The teardown invariant is trigger-agnostic, so it
        // is pinned with the deterministic failure; the kernel-dependent
        // timeout flavor is flagged in docs/review-log.md.)
        write_msg(
            &mut stream,
            &ClientMessage::Request {
                id: 1,
                request: Request::Ping {
                    nonce: "ping".into(),
                },
            },
        )
        .unwrap();

        // The client never reads and NEVER closes (`stream` stays alive):
        // pre-fix the writer exited on the failed write and nothing else
        // happened — the reserved slot stayed while the dispatcher polled
        // its open read half forever. The session must instead tear down
        // promptly after the writer's failure.
        let deadline = Instant::now() + Duration::from_secs(10);
        while handler.event_bus().active_sessions() != 0 {
            assert!(
                Instant::now() < deadline,
                "the session outlived its failed writer — a held-open client \
                 keeps its reserved slot after the writer died"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // The subscription went away too (the teardown guards ran).
        let deadline = Instant::now() + Duration::from_secs(5);
        while handler.event_bus().session_count() != 0 {
            assert!(
                Instant::now() < deadline,
                "subscription leaked after the writer-failure teardown"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // FU-3 (rust-review round-5 follow-up, Low): the assertions above
        // observe only SERVER-side counters — the client-visible half of
        // the 842c0c1 contract ("the writer takes the session down AND
        // the client learns of it") was pinned by nothing. A bounded read
        // must observe EOF: it fails whenever the teardown completes on
        // the server side while the socket (or its write half) stays
        // alive anywhere else — e.g. a weakened shutdown paired with a
        // strong reference that outlives the session (the exact class
        // the Weak SessionWorker handle exists to prevent). A client
        // blocked reading its response would otherwise hang forever.
        use std::io::Read;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0u8; 1];
        // `== Ok(0)` in assert form: any Err (a read timeout above all —
        // the Shutdown::Read mutation's signature) fails the expect; a
        // successful read must be the 0-byte EOF.
        assert_eq!(
            stream
                .read(&mut byte)
                .expect("the client's read must answer within the timeout"),
            0,
            "the failed writer must deliver EOF to its client — a client \
             blocked reading its response would hang forever"
        );
        stop.store(true, Ordering::SeqCst);
        let _ = served.join();
    }

    /// Shrinks a stream's `SO_RCVBUF` (std exposes no UnixStream helper) so
    /// a frame a few hundred KiB long cannot fit without the peer reading —
    /// host-independent blocking regardless of kernel buffer defaults.
    fn set_rcvbuf(stream: &UnixStream, bytes: usize) {
        nix::sys::socket::setsockopt(stream, nix::sys::socket::sockopt::RcvBuf, &bytes)
            .expect("SO_RCVBUF applies");
    }
}
