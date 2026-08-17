//! `protonwire-gui` — the Tauri shell (PRD 9.10, FR-127G).
//!
//! The shell owns the shared client SDK connection and maps an explicit,
//! minimal allowlist of typed GUI commands onto SDK calls. Milestone 1
//! exposes exactly one command (`daemon_state`); connection lifecycle,
//! selection, profiles, and settings commands join with their SDK
//! counterparts in later milestones. The webview loads bundled local assets
//! only, under a restrictive CSP (inline styles permitted for the bundled
//! shell's own markup), with no generic shell, filesystem, process, or
//! network bridge.
//!
//! R9-5: the command is async per Tauri v2's conventions and its blocking
//! SDK I/O (connect + GetState) runs on the async runtime's blocking pool,
//! never on the command-dispatch thread — a stalled daemon can no longer
//! freeze webview repaint/window handling for the SDK's deadlines (the GUI
//! counterpart of the TUI's R7-3 background refresh thread). A short
//! GUI-path request deadline turns a stalled daemon into the webview's
//! explicit unreachable state instead of a long pending invoke.

use std::path::PathBuf;
use std::time::Duration;

use protonwire_client::{ClientError, IpcSecurityChecks, ProtonwireClient};
use protonwire_frontend_api::ClientSurface;

/// How long the GUI path waits on any single daemon exchange (R9-5):
/// short enough that a stalled daemon renders the webview's explicit
/// unreachable state promptly instead of holding the invoke pending for
/// the SDK's 10 s default deadline. The hello handshake keeps the SDK's
/// own bound — it runs on the blocking pool, off the dispatch thread, so
/// it cannot freeze the webview either.
const DAEMON_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// The one Milestone 1 command: a full daemon state snapshot (R9-5).
///
/// `async` per Tauri v2's command conventions: the macro's async arm hands
/// the returned future to `InvokeResolver::respond_async_serialized`,
/// which spawns it onto tauri's async runtime, so the dispatch thread only
/// CREATES the future — it never runs this body. The body itself never
/// blocks either: it resolves the (cheap, pure) production socket and
/// trust-check defaults — exactly the resolution `connect_default`
/// performs — and awaits [`daemon_query`], which runs the blocking SDK I/O
/// on the blocking pool.
#[tauri::command]
async fn daemon_state() -> Result<serde_json::Value, String> {
    let socket = protonwire_client::resolve_socket_path(
        None,
        std::env::var(protonwire_client::SOCKET_ENV).ok().as_deref(),
    );
    let checks = protonwire_client::security_checks_from_env();
    daemon_query(socket, checks).await
}

/// The daemon query off the dispatch thread (R9-5): the blocking
/// connect+fetch+shape closure is submitted to tauri's blocking pool
/// (`async_runtime::spawn_blocking`) and the command merely awaits the
/// join handle, so a stalled daemon pins a pool worker — not the thread
/// Tauri uses to dispatch commands and repaint the webview. If the
/// blocking task panics, the join error surfaces as the command's error
/// instead of stranding the future.
async fn daemon_query(
    socket: PathBuf,
    checks: IpcSecurityChecks,
) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut client = ProtonwireClient::connect_to(&socket, ClientSurface::Gui, checks)
            .map_err(|e| e.to_string())?;
        fetch_state(&mut client)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The fetch-and-shape core of [`daemon_state`] over an established
/// session (R9-5): apply the GUI request deadline, then one GetState round
/// trip, shaped for the webview. Extracted as a unit so the deadline is
/// pinnable against a stubbed stalled daemon.
fn fetch_state(client: &mut ProtonwireClient) -> Result<serde_json::Value, String> {
    client.set_request_timeout(DAEMON_REQUEST_TIMEOUT);
    let state = client.state().map_err(|e| e.to_string())?;
    serde_json::to_value(state).map_err(|e| e.to_string())
}

/// Exit-code mapping kept for the future tray/notification surface.
#[allow(dead_code)]
fn daemon_exit_code(e: &ClientError) -> u8 {
    e.exit_code()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![daemon_state])
        .run(tauri::generate_context!())
        .expect("protonwire-gui shell failed to start");
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use protonwire_frontend_api::{
        ClientMessage, DaemonState, NetworkIntegration, PROTOCOL_VERSION, Request, RequestResult,
        RpcError, RpcErrorCode, ServerMessage, VpnState,
    };

    use super::*;

    // The fixture below deliberately adds NO dev-dependencies: the
    // dep-graph gate forbids a protonwire-gui -> protonwire-ipc edge even
    // test-only (frontends reach the daemon through protonwire-client,
    // T-23), so the client SDK's TestServer/frame helpers are off limits
    // here. The two helpers below restate the frame codec's documented
    // layout (crates/ipc/src/frame.rs: 4-byte big-endian payload length,
    // then the JSON payload) over std sockets, and the scratch directory
    // replaces tempfile. Everything else mirrors the scripted daemon-side
    // peers the client SDK's own tests use.

    /// Reads one length-prefixed JSON frame (the ipc codec's layout).
    fn read_frame<S: Read>(stream: &mut S) -> std::io::Result<ClientMessage> {
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix)?;
        let mut payload = vec![0u8; u32::from_be_bytes(prefix) as usize];
        stream.read_exact(&mut payload)?;
        serde_json::from_slice(&payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Writes one length-prefixed JSON frame (the ipc codec's layout).
    fn write_frame<S: Write>(stream: &mut S, message: &ServerMessage) -> std::io::Result<()> {
        let payload = serde_json::to_vec(message).unwrap();
        stream.write_all(&(payload.len() as u32).to_be_bytes())?;
        stream.write_all(&payload)?;
        stream.flush()
    }

    /// A unique per-test scratch directory under the system temp dir,
    /// best-effort removed on drop. Stands in for tempfile so the crate
    /// keeps zero dev-dependencies.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique =
                u64::from(std::process::id()) * 1_000_000 + COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!("protonwire-gui-test-{tag}-{unique}"));
            std::fs::create_dir_all(&path).expect("scratch dir creates");
            Self(path)
        }

        fn socket(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The snapshot a serving test daemon hands out.
    fn test_state() -> DaemonState {
        DaemonState {
            protocol_version: PROTOCOL_VERSION,
            daemon_version: "test-daemon".into(),
            vpn_state: VpnState::Disconnected,
            network_integration: NetworkIntegration::Auto,
            active_owner_uid: None,
            latest_event_seq: Some(0),
        }
    }

    /// Serves one client session: handshake, then GetState/Ping replies
    /// until the client disconnects.
    fn serve_session(mut peer: UnixStream) -> std::io::Result<()> {
        // Handshake.
        read_frame(&mut peer)?;
        write_frame(
            &mut peer,
            &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                protocol_version: 1,
                daemon_version: "test-daemon".into(),
                latest_event_seq: 0,
            }),
        )?;
        // Serve until the client hangs up.
        while let Ok(ClientMessage::Request { id, request }) = read_frame(&mut peer) {
            let result = match request {
                Request::GetState => RequestResult::State {
                    state: test_state(),
                },
                Request::Ping { nonce } => RequestResult::Pong { nonce },
                other => {
                    let error = RpcError::new(RpcErrorCode::NotImplemented, format!("{other:?}"));
                    write_frame(
                        &mut peer,
                        &ServerMessage::Response(protonwire_frontend_api::Response::Error {
                            id,
                            error,
                        }),
                    )?;
                    continue;
                }
            };
            write_frame(
                &mut peer,
                &ServerMessage::Response(protonwire_frontend_api::Response::Ok { id, result }),
            )?;
        }
        Ok(())
    }

    /// Binds a serving test daemon on `dir/serving.sock`: completes the
    /// handshake, then answers every GetState/Ping request until the
    /// client disconnects.
    fn spawn_serving_daemon(dir: &ScratchDir) -> PathBuf {
        let path = dir.socket("serving.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let Ok((peer, _)) = listener.accept() else {
                return;
            };
            let _ = serve_session(peer);
        });
        path
    }

    /// Binds a STALLED test daemon on `dir/stalled.sock`: it completes the
    /// hello handshake, then swallows every request forever — the R9-5
    /// finding's freeze condition, scripted the same way the client SDK's
    /// own unresponsive-daemon test scripts its silent peer.
    fn spawn_stalled_daemon(dir: &ScratchDir) -> PathBuf {
        let path = dir.socket("stalled.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let Ok((mut peer, _)) = listener.accept() else {
                return;
            };
            // Handshake, then silence forever: read and drop everything.
            let _ = read_frame(&mut peer);
            let _ = write_frame(
                &mut peer,
                &ServerMessage::HelloAck(protonwire_frontend_api::HelloAck {
                    protocol_version: 1,
                    daemon_version: "stalled".into(),
                    latest_event_seq: 0,
                }),
            );
            while read_frame(&mut peer).is_ok() {}
        });
        path
    }

    fn dev_checks() -> IpcSecurityChecks {
        IpcSecurityChecks::dev_unchecked()
    }

    /// R9-5 pin 1 — the extracted fetch-and-shape unit: a serving daemon's
    /// snapshot crosses as the JSON the webview renders.
    #[test]
    fn fetch_and_shape_round_trips_a_serving_daemon() {
        let dir = ScratchDir::new("serving");
        let path = spawn_serving_daemon(&dir);
        let mut client =
            ProtonwireClient::connect_to(&path, ClientSurface::Gui, dev_checks()).unwrap();
        let value = fetch_state(&mut client).expect("a serving daemon yields its snapshot");
        assert_eq!(value["daemon_version"], "test-daemon");
        assert_eq!(value["vpn_state"], "disconnected");
    }

    /// R9-5 pin 2 — the GUI deadline: a stalled daemon must surface an
    /// explicit unreachable error within the SHORT GUI request deadline,
    /// not the SDK's 10 s default, so the webview leaves its pending state.
    #[test]
    fn stalled_daemon_fails_within_the_gui_deadline() {
        let dir = ScratchDir::new("stalled-unit");
        let path = spawn_stalled_daemon(&dir);
        let mut client =
            ProtonwireClient::connect_to(&path, ClientSurface::Gui, dev_checks()).unwrap();

        let started = Instant::now();
        let err = fetch_state(&mut client).expect_err("a stalled daemon must not answer");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "the GUI query hung {elapsed:?} on a stalled daemon — the short \
             GUI deadline is not applied"
        );
        assert!(
            err.to_lowercase().contains("timed out") || err.to_lowercase().contains("unavailable"),
            "the error must name the unreachable daemon, got: {err}"
        );
    }

    /// R9-5 pin 3 — off the dispatch thread: polling the daemon-query
    /// future must return `Pending` immediately while the stalled daemon
    /// holds the SDK call, proving the blocking connect+GetState runs on a
    /// pool worker — the dispatch thread only ever polls this future
    /// (which is all Tauri's async command responder asks of it). A query
    /// executed inline on the poller blocks this first poll for the whole
    /// request deadline (the observed red: 10 s).
    #[test]
    fn first_poll_returns_pending_while_the_stalled_daemon_is_queried() {
        use std::task::{Context, Poll, Waker};

        let dir = ScratchDir::new("stalled-future");
        let path = spawn_stalled_daemon(&dir);
        let query = daemon_query(path, dev_checks());

        // A no-op waker: the pin observes the poll's outcome and timing,
        // never a wake-driven retry.
        let mut cx = Context::from_waker(Waker::noop());
        let mut query = std::pin::pin!(query);
        let started = Instant::now();
        let poll = query.as_mut().poll(&mut cx);
        let elapsed = started.elapsed();
        assert!(
            matches!(poll, Poll::Pending),
            "the first poll completed inline — the SDK call runs on the polling \
             (dispatch) thread"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "the first poll blocked {elapsed:?} — the stalled daemon's SDK call \
             is pinning the polling (dispatch) thread"
        );

        // Driven to completion on the async runtime, the query must yield
        // the same explicit unreachable error the unit pin covers — the
        // off-thread shape changes WHERE the deadline runs out, not what
        // the webview receives.
        let started = Instant::now();
        let err = tauri::async_runtime::block_on(query)
            .expect_err("the stalled daemon must surface its timeout");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the query did not bound the stalled daemon"
        );
        assert!(
            err.to_lowercase().contains("timed out") || err.to_lowercase().contains("unavailable"),
            "the error must name the unreachable daemon, got: {err}"
        );
    }
}
