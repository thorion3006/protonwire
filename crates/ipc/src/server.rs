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
use crate::bus::EventBus;
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

/// Maximum simultaneously served sessions; connections beyond this are
/// accepted and immediately closed to drain the backlog.
const MAX_SESSIONS: usize = 64;

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
    /// Sessions are bounded ([`MAX_SESSIONS`]), must complete the handshake
    /// within [`HELLO_DEADLINE`], and cannot pin a writer past
    /// [`WRITE_TIMEOUT`].
    pub fn serve<H: RequestHandler + 'static>(&self, handler: Arc<H>, stop: Arc<AtomicBool>) {
        // Poll-accept so shutdown is responsive without signal plumbing here.
        if let Err(e) = self.listener.set_nonblocking(true) {
            warn!("cannot switch accept loop to nonblocking mode: {e}");
            return;
        }
        while !stop.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if handler.event_bus().session_count() >= MAX_SESSIONS {
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
    let (writer_tx, writer_rx) = mpsc::sync_channel::<ServerMessage>(256);
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
    drop(writer_tx);
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
                if protocol_version > PROTOCOL_VERSION {
                    let _ = writer_tx.send(ServerMessage::HelloError(HelloError {
                        supported_version: PROTOCOL_VERSION,
                        reason: "unsupported-protocol-version".into(),
                    }));
                    return Ok(());
                }
                let client = client.sanitized();
                info!(uid = peer.uid, name = %client.name, "client connected");
                let _ = writer_tx.send(ServerMessage::HelloAck(HelloAck {
                    // Speak the highest version both sides support.
                    protocol_version: protocol_version.min(PROTOCOL_VERSION),
                    daemon_version: handler.daemon_version().to_owned(),
                    latest_event_seq: handler.latest_event_seq(),
                }));
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
