//! Daemon-side plumbing shared by `main` and tests: the event-sink bridge
//! and the request handler that couples core to the admin stop flag.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use protonwire_core::DaemonCore;
use protonwire_frontend_api::{Request, RequestResult, RpcError};
use protonwire_ipc::{EventBus, RequestHandler, SessionContext};

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
