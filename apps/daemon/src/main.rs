//! `protonwire-daemon` — the privileged host (PRD 6.1).
//!
//! The daemon is deliberately thin: it loads and validates configuration,
//! constructs [`protonwire_core::DaemonCore`], serves the frontend API over
//! a Unix socket with peer-credential authorization, and owns process
//! lifecycle. All product behavior lives in core; the request handler and
//! event-sink bridge live in this crate's library so they are unit-testable.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use clap::Parser;
use protonwire_core::redact::init_tracing_filtered;
use protonwire_store::config::SystemConfig;
use protonwire_store::paths::ConfigPaths;
use tracing::info;

use protonwire_daemon::{BusSink, DaemonHandler};

#[derive(Debug, Parser)]
#[command(
    name = "protonwire-daemon",
    version,
    about = "ProtonWire daemon (privileged host)"
)]
struct Args {
    /// System configuration path (default: /etc/protonwire/config.yaml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// IPC socket directory (default: /run/protonwire).
    #[arg(long)]
    socket_dir: Option<PathBuf>,
    /// Log level filter (overrides `daemon.log_level` from the config;
    /// RUST_LOG overrides both).
    #[arg(long)]
    log_level: Option<String>,
}

fn main() {
    let args = Args::parse();

    let mut paths = ConfigPaths::system();
    if let Some(config) = &args.config {
        paths.system_config = config.clone();
    }
    if let Some(socket_dir) = &args.socket_dir {
        paths.socket_dir = socket_dir.clone();
    }

    // Configuration is loaded before tracing initializes so that
    // `daemon.log_level` from the config applies (rust-review finding 7);
    // a `--log-level` flag wins over the config, and RUST_LOG wins over
    // both. Load failures predate the logger and go to stderr.
    let config = match SystemConfig::load(&paths.system_config) {
        Ok(config) => Arc::new(config),
        Err(e) => {
            eprintln!("protonwire-daemon: {e}");
            std::process::exit(15); // PRD 9.8: config validation failed
        }
    };
    let level = args
        .log_level
        .clone()
        .unwrap_or_else(|| config.daemon.log_level.clone());
    init_tracing_filtered(&level);

    // Codex PR review finding 4: capture daemon.socket_path before `config`
    // moves into the core; binding applies it with --socket-dir > config >
    // default precedence (see resolve_bind_location).
    let config_socket_path = config.daemon.socket_path.clone();
    let bus = Arc::new(protonwire_ipc::EventBus::new());
    let core = Arc::new(protonwire_core::DaemonCore::new(
        env!("CARGO_PKG_VERSION"),
        config,
        Arc::new(BusSink(Arc::clone(&bus))),
    ));
    let (socket_dir, socket_name) = protonwire_daemon::resolve_bind_location(
        args.socket_dir.as_deref(),
        config_socket_path.as_deref(),
        &paths.socket_dir,
        &paths.socket_name,
    );
    let server = match protonwire_ipc::server::IpcServer::bind(&socket_dir, &socket_name) {
        Ok(server) => server,
        Err(e) => {
            eprintln!(
                "protonwire-daemon: cannot bind {}: {e}",
                socket_dir.join(&socket_name).display()
            );
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
