//! Daemon-side plumbing shared by `main` and tests: the event-sink bridge
//! and the request handler that couples core to the admin stop flag.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use protonwire_core::DaemonCore;
use protonwire_frontend_api::{Request, RequestResult, RpcError};
use protonwire_ipc::{EventBus, RequestHandler, SessionContext};

use std::path::{Path, PathBuf};

/// Resolves where the IPC server binds (Codex PR review finding 4):
/// the `--socket-dir` CLI override wins, then the config document's
/// `daemon.socket_path` (split into directory and name), then the default
/// `ConfigPaths` location. Pure so the precedence is unit-testable —
/// `main` only wires it into
/// [`protonwire_ipc::server::IpcServer::bind_with_group`] (with
/// `daemon.socket_group` alongside, pr-champion WO-7).
pub fn resolve_bind_location(
    cli_socket_dir: Option<&Path>,
    config_socket_path: Option<&str>,
    default_dir: &Path,
    default_name: &str,
) -> (PathBuf, String) {
    if let Some(dir) = cli_socket_dir {
        return (dir.to_path_buf(), default_name.to_owned());
    }
    if let Some(path) = config_socket_path {
        let path = Path::new(path);
        let dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(default_name);
        return (dir.to_path_buf(), name.to_owned());
    }
    (default_dir.to_path_buf(), default_name.to_owned())
}
/// Bridges core events to the IPC event bus.
pub struct BusSink(pub Arc<EventBus>);

impl protonwire_core::EventSink for BusSink {
    fn publish(&self, event: protonwire_frontend_api::EventEnvelope) {
        self.0
            .publish(protonwire_frontend_api::ServerMessage::Event(event));
    }
}

/// Serves core requests plus the admin shutdown path.
pub struct DaemonHandler {
    /// The authoritative state machine.
    pub core: Arc<DaemonCore>,
    /// Set when an administrator requests shutdown; the serve loop exits.
    pub stop: Arc<AtomicBool>,
    /// Event fan-out shared with sessions.
    pub bus: Arc<EventBus>,
}

impl RequestHandler for DaemonHandler {
    fn daemon_version(&self) -> &str {
        self.core.version()
    }

    fn latest_event_seq(&self) -> u64 {
        self.core.latest_event_seq()
    }

    fn handle(&self, ctx: &SessionContext, request: Request) -> Result<RequestResult, RpcError> {
        match request {
            Request::Shutdown => {
                // authz already restricted this to administrator peers.
                tracing::info!(uid = ctx.peer.uid, "administrator requested shutdown");
                self.stop.store(true, Ordering::SeqCst);
                Ok(RequestResult::Acknowledged)
            }
            other => self.core.handle_request(ctx.peer.uid, other),
        }
    }

    fn event_bus(&self) -> &EventBus {
        &self.bus
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protonwire_frontend_api::RpcErrorCode;
    use protonwire_store::config::SystemConfig;

    fn handler() -> (DaemonHandler, Arc<AtomicBool>) {
        let stop = Arc::new(AtomicBool::new(false));
        let core = Arc::new(DaemonCore::new(
            "0.1.0-test",
            Arc::new(SystemConfig::default()),
            Arc::new(BusSink(Arc::new(EventBus::new()))),
        ));
        let handler = DaemonHandler {
            core,
            stop: Arc::clone(&stop),
            bus: Arc::new(EventBus::new()),
        };
        (handler, stop)
    }

    fn admin_ctx() -> SessionContext {
        SessionContext {
            peer: protonwire_ipc::PeerCredentials {
                uid: 0,
                gid: 0,
                pid: None,
            },
            client: protonwire_frontend_api::ClientInfo {
                name: "test".into(),
                version: "0".into(),
                surface: protonwire_frontend_api::ClientSurface::Other,
            },
        }
    }

    #[test]
    fn admin_shutdown_sets_stop_flag_and_acknowledges() {
        let (handler, stop) = handler();
        assert!(!stop.load(Ordering::SeqCst));
        match handler.handle(&admin_ctx(), Request::Shutdown).unwrap() {
            RequestResult::Acknowledged => {}
            other => panic!("unexpected result: {other:?}"),
        }
        assert!(stop.load(Ordering::SeqCst));
    }

    #[test]
    fn other_requests_delegate_to_core() {
        let (handler, _) = handler();
        // Ping succeeds through the core delegation.
        match handler
            .handle(&admin_ctx(), Request::Ping { nonce: "n".into() })
            .unwrap()
        {
            RequestResult::Pong { nonce } => assert_eq!(nonce, "n"),
            other => panic!("unexpected result: {other:?}"),
        }
        // Disconnect is refused by core until Milestone 4.
        let err = handler
            .handle(&admin_ctx(), Request::Disconnect)
            .unwrap_err();
        assert_eq!(err.code, RpcErrorCode::NotImplemented);
    }
}

#[cfg(test)]
mod bind_location_tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Codex PR review finding 4 (P2): the documented `daemon.socket_path`
    /// config value was accepted and validated but never applied — binding
    /// always used ConfigPaths/--socket-dir. Precedence under test:
    /// CLI --socket-dir > config daemon.socket_path > default location.
    #[test]
    fn socket_bind_location_precedence() {
        let default_dir = Path::new("/run/protonwire");
        let default_name = "protonwire.sock";

        // CLI flag wins over everything, including the config value.
        assert_eq!(
            resolve_bind_location(
                Some(Path::new("/run/test-cli")),
                Some("/custom/daemon.sock"),
                default_dir,
                default_name,
            ),
            (PathBuf::from("/run/test-cli"), "protonwire.sock".to_owned())
        );

        // Config value wins over the default when no CLI flag is given.
        assert_eq!(
            resolve_bind_location(None, Some("/var/run/alt.sock"), default_dir, default_name),
            (PathBuf::from("/var/run"), "alt.sock".to_owned())
        );

        // Bare name: relative to the working directory, not the default dir.
        assert_eq!(
            resolve_bind_location(None, Some("relative.sock"), default_dir, default_name),
            (PathBuf::from("."), "relative.sock".to_owned())
        );

        // Nothing configured: the documented default.
        assert_eq!(
            resolve_bind_location(None, None, default_dir, default_name),
            (
                PathBuf::from("/run/protonwire"),
                "protonwire.sock".to_owned()
            )
        );
    }
}
