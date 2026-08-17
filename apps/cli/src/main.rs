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

#[cfg(test)]
mod parse_tests {
    use super::*;
    use clap::Parser;
    use commands::Command;

    /// Codex PR review finding 7 (P2): trailing_var_arg on the Connect
    /// target swallowed every token after the first target word — including
    /// `--by latency` — so the documented invocation
    /// `protonwire connect country GB --by latency` failed parsing.
    #[test]
    fn connect_options_after_target_words_parse() {
        let cli = Cli::try_parse_from([
            "protonwire",
            "connect",
            "country",
            "GB",
            "--by",
            "latency",
            "--protocol",
            "stealth",
            "--dry-run",
            "--json",
        ])
        .expect("options after target words must parse");
        match cli.command {
            Command::Connect {
                target,
                by,
                protocol,
                dry_run,
                json,
            } => {
                assert_eq!(target, ["country", "GB"]);
                assert_eq!(by.as_deref(), Some("latency"));
                assert_eq!(protocol.as_deref(), Some("stealth"));
                assert!(dry_run);
                assert!(json);
            }
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    /// The multi-word target grammar still parses without any options.
    #[test]
    fn connect_bare_multiword_target_still_parses() {
        let cli = Cli::try_parse_from(["protonwire", "connect", "server", "UK#42"])
            .expect("bare multi-word target must parse");
        match cli.command {
            Command::Connect { target, by, .. } => {
                assert_eq!(target, ["server", "UK#42"]);
                assert_eq!(by, None);
            }
            other => panic!("expected Connect, got {other:?}"),
        }
    }

    /// Review finding: PRD documents `protonwire servers refresh [--yes]`
    /// (~789-790, ~2059), but `refresh` was a positional SetTrue flag, so
    /// clap's debug asserts panicked on parse — the documented invocation
    /// crashed instead of reaching the milestone-2 refusal.
    #[test]
    fn servers_refresh_parses_as_documented_subcommand() {
        let cli = Cli::try_parse_from(["protonwire", "servers", "refresh"])
            .expect("`servers refresh` must parse (PRD 9.4)");
        match cli.command {
            Command::Servers {
                sub: Some(commands::ServersSub::Refresh { yes }),
            } => assert!(!yes),
            other => panic!("expected Servers refresh, got {other:?}"),
        }

        let cli = Cli::try_parse_from(["protonwire", "servers", "refresh", "--yes"])
            .expect("`servers refresh --yes` must parse (PRD 9.4)");
        match cli.command {
            Command::Servers {
                sub: Some(commands::ServersSub::Refresh { yes }),
            } => assert!(yes, "--yes must be accepted"),
            other => panic!("expected Servers refresh, got {other:?}"),
        }
    }

    /// The bare `servers` listing keeps parsing and refuses with its
    /// planned milestone, subcommand or not.
    #[test]
    fn bare_servers_still_parses() {
        let cli =
            Cli::try_parse_from(["protonwire", "servers"]).expect("bare `servers` must parse");
        match cli.command {
            Command::Servers { sub: None } => {}
            other => panic!("expected bare Servers, got {other:?}"),
        }
    }

    /// Select keeps the same target grammar; a future option must not be
    /// swallowed by it either.
    #[test]
    fn select_target_stops_at_flags() {
        // `select` has no options today; the positional must still stop at
        // one so the error is clap's "unexpected argument", not silent
        // capture into the target words.
        let err = Cli::try_parse_from(["protonwire", "select", "fastest", "--json"]);
        assert!(
            err.is_err(),
            "unknown select options must not become target words"
        );
    }
}
