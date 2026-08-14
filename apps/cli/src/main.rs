//! `protonwire` — the CLI (PRD 9.1, FR-127E).
//!
//! Milestone 1 implements `status` (human and JSON), `--version`, and the
//! `daemon status`/`stop` lifecycle surface against the real daemon
//! (`daemon start` defers to the systemd unit, which lands in Milestone 8).
//! Every other command in the tree is present with an honest
//! not-implemented-in-this-milestone refusal and its planned milestone,
//! so the command grammar is stable from day one.

mod commands;
mod target;

use std::path::{Path, PathBuf};

use clap::Parser;
use commands::Command;

use protonwire_client::{ClientError, ProtonwireClient};

/// Global options shared by every subcommand.
#[derive(Debug, Parser)]
#[command(
    name = "protonwire",
    version,
    about = "ProtonWire — Proton VPN control plane for Linux"
)]
struct Cli {
    /// Daemon socket path (default: $PROTONWIRE_SOCKET or
    /// /run/protonwire/protonwire.sock).
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    /// Never prompt; fail instead of asking (PRD FR-127E).
    #[arg(long, global = true)]
    no_input: bool,

    #[command(subcommand)]
    command: Command,
}

fn main() {
    let cli = Cli::parse();
    let code = match commands::run(&cli.command, cli.socket.as_deref(), cli.no_input) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("protonwire: {e}");
            e.exit_code()
        }
    };
    std::process::exit(i32::from(code));
}

/// Connects a client honoring the socket override, or the SDK defaults.
/// The trust-check policy (including the debug-only bypass) lives in the
/// SDK, not here (refactorer step 3).
pub(crate) fn connect(socket: Option<&Path>) -> Result<ProtonwireClient, ClientError> {
    protonwire_client::connect_with_socket_override(
        socket,
        protonwire_frontend_api::ClientSurface::Cli,
    )
}
