//! `protonwire-daemon` — the privileged host (PRD 6.1).
//!
//! The daemon is deliberately thin: it loads and validates configuration,
//! constructs [`protonwire_core::DaemonCore`], serves the frontend API over
//! a Unix socket with peer-credential authorization, and owns process
//! lifecycle. All product behavior lives in core.
//!
//! Shutdown paths in Milestone 1:
//! * `protonwire daemon stop` (administrator IPC request)
//! * process exit (the next bind recovers: stale sockets are detected and
//!   removed, live sockets are refused)
//!
//! SIGTERM handling arrives with the systemd unit in Milestone 8, which is
//! also when the capability sandbox (`CAP_NET_ADMIN` base) is enforced.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use protonwire_core::redact::init_tracing_filtered;
use protonwire_frontend_api::{Request, RequestResult, RpcError, RpcErrorCode};
use protonwire_ipc::{EventBus, RequestHandler, SessionContext};
use protonwire_store::config::SystemConfig;
use protonwire_store::paths::ConfigPaths;
use tracing::info;

#[derive(Debug, Parser)]
#[command(name = "protonwire-daemon", version, about = "ProtonWire daemon (privileged host)")]
struct Args {
    /// System configuration path (default: /etc/protonwire/config.yaml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// IPC socket directory (default: /run/protonwire).
    #[arg(long)]
    socket_dir: Option<PathBuf>,
    /// Daemon state file (default: /var/lib/protonwire/state.json).
    #[arg(long)]
    state_file: Option<PathBuf>,
    /// Log level filter (default: info; RUST_LOG overrides).
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// Bridges core events to the IPC event bus.
struct BusSink(Arc<EventBus>);

impl protonwire_core::EventSink for BusSink {
    fn publish(&self, event: protonwire_frontend_api::EventEnvelope) {
        self.0.publish(protonwire_frontend_api::ServerMessage::Event(event));
    }
}

/// Serves core requests plus the admin shutdown path.
struct DaemonHandler {
    core: Arc<protonwire_core::DaemonCore>,
    stop: Arc<AtomicBool>,
    bus: Arc<EventBus>,
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
                info!(uid = ctx.peer.uid, "administrator requested shutdown");
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

fn main() {
    let args = Args::parse();
    init_tracing_filtered(&args.log_level);

    let mut paths = ConfigPaths::system();
    if let Some(config) = &args.config {
        paths.system_config = config.clone();
    }
    if let Some(socket_dir) = &args.socket_dir {
        paths.socket_dir = socket_dir.clone();
    }
    if let Some(state_file) = &args.state_file {
        paths.state_file = state_file.clone();
    }

    let config = match SystemConfig::load(&paths.system_config) {
        Ok(config) => Arc::new(config),
        Err(e) => {
            eprintln!("protonwire-daemon: {e}");
            std::process::exit(15); // PRD 9.8: config validation failed
        }
    };

    let bus = Arc::new(EventBus::new());
    let core = Arc::new(protonwire_core::DaemonCore::new(
        env!("CARGO_PKG_VERSION"),
        config,
        Arc::new(BusSink(Arc::clone(&bus))),
    ));

    let server = match protonwire_ipc::server::IpcServer::bind(&paths.socket_dir, &paths.socket_name)
    {
        Ok(server) => server,
        Err(e) => {
            eprintln!("protonwire-daemon: cannot bind {}: {e}", paths.socket_path().display());
            std::process::exit(1);
        }
    };

    core.notice(
        protonwire_frontend_api::NoticeLevel::Info,
        "daemon started (milestone 1 foundation)",
    );

    let stop = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(DaemonHandler {
        core: Arc::clone(&core),
        stop: Arc::clone(&stop),
        bus,
    });

    info!(
        socket = %server.socket_path().display(),
        version = env!("CARGO_PKG_VERSION"),
        "protonwire-daemon serving"
    );
    server.serve(handler, stop);
    info!("protonwire-daemon stopped");
}
