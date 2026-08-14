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
use std::time::Duration;

use protonwire_frontend_api::{
    ClientInfo, ClientMessage, EventEnvelope, HelloAck, PROTOCOL_VERSION, Request, RequestResult,
    Response, RpcError, RpcErrorCode, ServerMessage,
};

use crate::frame::{read_msg, write_msg};
use crate::peer::PeerCredentials;

/// Default request timeout.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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

/// A connected, handshaken client transport.
///
/// Events that arrive while waiting for a response are buffered and returned
/// by [`IpcClient::next_event`].
pub struct IpcClient {
    stream: UnixStream,
    next_id: u64,
    pending_events: VecDeque<EventEnvelope>,
    timeout: Duration,
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
        let mut transport = Self {
            stream,
            next_id: 0,
            pending_events: VecDeque::new(),
            timeout,
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

    /// Overrides the per-request read timeout (tests use short values).
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
        let _ = self.stream.set_read_timeout(Some(timeout));
    }

    fn handshake(&mut self, client: ClientInfo) -> Result<HelloAck, ConnectError> {
        write_msg(
            &mut self.stream,
            &ClientMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
                client,
            },
        )
        .map_err(|e| ConnectError::Protocol(e.to_string()))?;
        match read_msg::<_, ServerMessage>(&mut self.stream) {
            Ok(ServerMessage::HelloAck(ack)) if ack.protocol_version <= PROTOCOL_VERSION => Ok(ack),
            Ok(ServerMessage::HelloError(err)) => Err(ConnectError::HandshakeRefused {
                supported_version: err.supported_version,
                reason: err.reason,
            }),
            Ok(other) => Err(ConnectError::Protocol(format!(
                "unexpected message during handshake: {other:?}"
            ))),
            Err(e) => Err(ConnectError::Protocol(e.to_string())),
        }
    }

    /// Sends a request and blocks for its correlated response.
    pub fn request(&mut self, request: Request) -> Result<RequestResult, RpcError> {
        let id = self.next_id;
        self.next_id += 1;
        write_msg(&mut self.stream, &ClientMessage::Request { id, request })
            .map_err(|e| RpcError::new(RpcErrorCode::Internal, format!("write failed: {e}")))?;
        loop {
            match read_msg::<_, ServerMessage>(&mut self.stream) {
                Ok(ServerMessage::Response(response)) => match response {
                    Response::Ok { id: seen, result } if seen == id => return Ok(result),
                    Response::Error { id: seen, error } if seen == id => return Err(error),
                    other => {
                        return Err(RpcError::new(
                            RpcErrorCode::Internal,
                            format!("out-of-order response id {}", other.id()),
                        ));
                    }
                },
                Ok(ServerMessage::Event(envelope)) => {
                    self.pending_events.push_back(envelope);
                }
                Ok(other) => {
                    return Err(RpcError::new(
                        RpcErrorCode::Internal,
                        format!("unexpected message mid-request: {other:?}"),
                    ));
                }
                Err(e) => {
                    return Err(RpcError::new(
                        RpcErrorCode::Internal,
                        format!("read failed: {e}"),
                    ));
                }
            }
        }
    }

    /// Returns the next buffered or socket event, blocking until one arrives.
    pub fn next_event(&mut self) -> io::Result<EventEnvelope> {
        if let Some(envelope) = self.pending_events.pop_front() {
            return Ok(envelope);
        }
        match read_msg::<_, ServerMessage>(&mut self.stream) {
            Ok(ServerMessage::Event(envelope)) => Ok(envelope),
            Ok(other) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected message while awaiting event: {other:?}"),
            )),
            Err(e) => Err(map_frame_error(e)),
        }
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
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use protonwire_frontend_api::VpnState;

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

    fn spawn_server(dir: &tempfile::TempDir) -> (PathBuf, Arc<AtomicBool>) {
        let handler = Arc::new(EchoHandler {
            version: "test-daemon".into(),
            bus: EventBus::new(),
            seq: AtomicU64::new(0),
        });
        let server = crate::server::IpcServer::bind(dir.path(), "test.sock").unwrap();
        let path = server.socket_path().to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        std::thread::spawn(move || server.serve(handler, stop2));
        (path, stop)
    }

    #[test]
    fn handshake_ping_and_state_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let (path, stop) = spawn_server(&dir);
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
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn error_response_preserves_code() {
        let dir = tempfile::tempdir().unwrap();
        let (path, stop) = spawn_server(&dir);
        let mut client =
            IpcClient::connect(&path, &test_client_info(), SecurityChecks::dev_unchecked())
                .unwrap();
        let err = client.request(Request::Shutdown).unwrap_err();
        assert_eq!(err.code, RpcErrorCode::PermissionDenied);
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn untrusted_socket_rejected_when_checks_strict() {
        let dir = tempfile::tempdir().unwrap();
        let (path, stop) = spawn_server(&dir);
        let err = IpcClient::connect(&path, &test_client_info(), SecurityChecks::strict())
            .err()
            .expect("strict checks must reject a non-root socket");
        match err {
            ConnectError::Untrusted { reason, .. } => {
                assert!(reason.contains("root") || reason.contains("writable"));
            }
            other => panic!("expected Untrusted, got {other:?}"),
        }
        stop.store(true, Ordering::SeqCst);
    }
}
