//! Daemon-side IPC server: bind, authenticate, dispatch, fan out events.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use protonwire_frontend_api::{
    ClientInfo, ClientMessage, HelloAck, HelloError, PROTOCOL_VERSION, Request, RequestResult,
    Response, RpcError, ServerMessage,
};
use tracing::{debug, info, warn};

use crate::authz::{authorize, required_role};
use crate::bus::{EventBus, MAX_SESSIONS};
use crate::frame::{FrameError, read_msg, write_msg};
use crate::peer::PeerCredentials;

/// Interval at which session loops wake to check the stop flag while blocked
/// on reads.
const READ_POLL: Duration = Duration::from_millis(250);

/// A connection must complete the hello handshake within this window.
const HELLO_DEADLINE: Duration = Duration::from_secs(5);

/// Ceiling on blocked writes to one client; a peer that stops reading loses
/// its session instead of pinning a writer thread forever.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

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
    pub fn serve<H: RequestHandler + 'static>(&self, handler: Arc<H>, stop: Arc<AtomicBool>) {
        // Poll-accept so shutdown is responsive without signal plumbing here.
        if let Err(e) = self.listener.set_nonblocking(true) {
            warn!("cannot switch accept loop to nonblocking mode: {e}");
            return;
        }
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
                    let handler = Arc::clone(&handler);
                    let stop = Arc::clone(&stop);
                    std::thread::spawn(move || {
                        if let Err(e) = std::panic::catch_unwind(AssertUnwindSafe(|| {
                            handle_session(stream, handler, stop)
                        })) {
                            warn!("IPC session panicked and was dropped: {e:?}");
                        }
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
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Refuses to remove a socket another daemon is actively serving.
fn ensure_not_live(socket_path: &Path) -> io::Result<()> {
    // Local Unix sockets connect immediately; a refused or failed connect
    // means no live listener owns the path.
    match UnixStream::connect(socket_path) {
        Ok(_) => Err(io::Error::other(format!(
            "another daemon is serving {}",
            socket_path.display()
        ))),
        Err(_) => Ok(()),
    }
}

fn set_socket_mode(socket_path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))
}

/// Serves one client connection until EOF, error, or daemon shutdown.
fn handle_session<H: RequestHandler>(stream: UnixStream, handler: Arc<H>, stop: Arc<AtomicBool>) {
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
    let Ok(read_half) = stream.try_clone() else {
        warn!("session rejected: socket clone failed");
        return;
    };
    let mut read_half = read_half;

    // Writer thread owns the write half exclusively; a write timeout bounds
    // how long a non-reading peer can pin it.
    if let Err(e) = stream.set_write_timeout(Some(WRITE_TIMEOUT)) {
        warn!("set_write_timeout failed: {e}");
        return;
    }
    let (writer_tx, writer_rx) = mpsc::sync_channel::<ServerMessage>(crate::bus::SESSION_QUEUE_LEN);
    let write_stream = stream;
    let writer = std::thread::spawn(move || {
        let mut write_half = write_stream;
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

    let result = serve_messages(&mut read_half, &writer_tx, &handler, &peer, &stop);
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
) -> Result<(), FrameError> {
    let connected_at = std::time::Instant::now();
    let mut hello_done = false;
    let mut client_info = None;
    while !stop.load(Ordering::SeqCst) {
        if !hello_done && connected_at.elapsed() > HELLO_DEADLINE {
            let _ = writer_tx.send(ServerMessage::HelloError(HelloError {
                supported_version: PROTOCOL_VERSION,
                reason: "hello-timeout".into(),
            }));
            return Ok(());
        }
        let message = match read_msg::<_, ClientMessage>(read_half) {
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
            std::thread::spawn(move || match std::os::unix::net::UnixStream::connect(&path) {
                Ok(stream) => {
                    let _ = tx.send(stream);
                }
                Err(_) => {
                    connect_error.fetch_add(1, Ordering::SeqCst);
                }
            });
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
}
