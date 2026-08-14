//! Command tree (PRD 9.1–9.7) and dispatch.

use std::path::Path;

use clap::Subcommand;
use protonwire_client::ClientError;
use protonwire_frontend_api::{DaemonState, RpcError, RpcErrorCode};

use crate::{connect, target::ConnectTargetArgs};

/// Every top-level command from PRD 9.1. Arguments are the full §9.2–9.7
/// grammar where the milestone implements it; otherwise the surface is
/// declared and refused with its planned milestone.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Sign in with your Proton account (Milestone 2).
    Login,
    /// Sign out and clear the session (Milestone 2).
    Logout,
    /// Show account, plan, and entitlement (Milestone 2).
    Account,
    /// Credential storage management (Milestone 2).
    Credentials {
        #[command(subcommand)]
        sub: Option<CredentialsSub>,
    },
    /// List available protocols (Milestone 4).
    Protocols,
    /// Show or set the network integration adapter (Milestone 5).
    Integration,
    /// Connect to a server or group (Milestone 4 for the tunnel).
    Connect {
        /// Target words, for example: fastest | country GB | server UK#42 |
        /// group proton:fastest-country (PRD 9.2).
        #[arg(value_name = "TARGET", trailing_var_arg = true, required = true)]
        target: Vec<String>,

        /// Ranking policy (official|balanced|load|latency; PRD 9.3).
        #[arg(long)]
        by: Option<String>,

        /// Protocol override (smart|wireguard-udp|wireguard-tcp|stealth).
        #[arg(long)]
        protocol: Option<String>,

        /// Resolve and print the selection without connecting (Milestone 3).
        #[arg(long)]
        dry_run: bool,

        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Change server within the current policy (Milestone 6).
    ChangeServer,
    /// Disconnect the active tunnel (Milestone 4).
    Disconnect,
    /// Reconnect with the last target (Milestone 4).
    Reconnect,
    /// Show connection status.
    Status {
        /// Machine-readable JSON status (PRD FR-118).
        #[arg(long)]
        json: bool,
    },
    /// List servers from the cached catalog (Milestone 2).
    Servers {
        /// Force a catalog refresh (warned + confirmed; Milestone 2).
        refresh: bool,
    },
    /// List connection groups (Milestone 3).
    Group,
    /// Resolve a target without connecting (Milestone 3).
    Select {
        #[arg(value_name = "TARGET", trailing_var_arg = true, required = true)]
        target: Vec<String>,
    },
    /// Show or set configuration (Milestone 2 for overlays).
    Config,
    /// Profile management (Milestone 6).
    Profile,
    /// Split tunneling management (Milestone 7).
    Split,
    /// DNS configuration (Milestone 5).
    Dns,
    /// Port forwarding control (Milestone 6).
    Port,
    /// Kill switch control (Milestone 5).
    Killswitch,
    /// LAN access control (Milestone 5).
    Lan,
    /// Daemon lifecycle.
    Daemon {
        #[command(subcommand)]
        sub: DaemonSub,
    },
    /// Diagnostics (Milestone 6).
    Debug {
        #[command(subcommand)]
        sub: Option<DebugSub>,
    },
}

/// `protonwire credentials` subcommands (PRD 9.6).
#[derive(Debug, Subcommand)]
pub enum CredentialsSub {
    /// Show credential storage status.
    Status,
    /// Migrate the writable session store.
    Migrate {
        /// Destination store.
        #[arg(long)]
        to: String,
    },
    /// Import a provisioned systemd session.
    ImportProvisionedSession {
        /// Destination store.
        #[arg(long)]
        to: String,
    },
    /// Drop any stored password.
    ForgetPassword,
}

/// `protonwire daemon` subcommands.
#[derive(Debug, Subcommand)]
pub enum DaemonSub {
    /// Start the daemon (managed by systemd; development runs the binary).
    Start,
    /// Stop the daemon (administrator only).
    Stop,
    /// Ping the daemon and show liveness.
    Status,
}

/// `protonwire debug` subcommands (PRD 7.16 examples).
#[derive(Debug, Subcommand)]
pub enum DebugSub {
    /// Watch daemon events.
    Events,
    /// Query recent logs.
    Logs,
    /// Produce a redacted diagnostic bundle.
    Bundle,
}

/// Dispatch outcome.
type RunResult = Result<(), ClientError>;

/// Runs one command. `no_input` gates interactive prompts (FR-127E).
///
/// Every path returns a typed error (mapped to PRD 9.8 exit codes by
/// `main`); nothing exits the process from in here, so the dispatch stays
/// unit-testable.
pub fn run(command: &Command, socket: Option<&Path>, no_input: bool) -> RunResult {
    let _ = no_input; // prompts arrive with Milestone 2 login flows
    match command {
        Command::Status { json } => status(socket, *json),
        Command::Daemon { sub } => daemon(sub, socket),
        Command::Connect {
            target,
            by,
            protocol,
            dry_run,
            json,
        } => {
            let _ = (by, protocol, dry_run, json);
            let target = ConnectTargetArgs::parse(target)?;
            connect_command(socket, target)
        }
        Command::Disconnect => {
            let mut client = connect(socket)?;
            client.disconnect_vpn()
        }
        // Everything else is declared surface with an honest refusal.
        cmd if planned(cmd) => Err(ClientError::Rpc(RpcError::new(
            RpcErrorCode::NotImplemented,
            format!(
                "`{}` is not implemented in milestone 1 (planned: {})",
                command_name(cmd),
                planned_milestone(cmd),
            ),
        ))),
        _ => unreachable!("all commands are either implemented or planned"),
    }
}

/// PRD 9.8 exit code 0 path for `status`.
fn status(socket: Option<&Path>, json: bool) -> RunResult {
    let mut client = connect(socket)?;
    let state = client.state()?;
    if json {
        println!("{}", status_json(&state));
    } else {
        print_status_human(&state);
    }
    Ok(())
}

/// Renders the FR-118 JSON status document from the daemon snapshot.
///
/// Milestone 1 exposes the disconnected-state subset: `state` and
/// `network_integration` with daemon metadata. Server, tunnel, and feature
/// sections join when the ProTUN engine lands (Milestone 4) — additive
/// fields, minor protocol bump.
pub(crate) fn status_json(state: &DaemonState) -> String {
    let mut document = serde_json::json!({
        "state": state.vpn_state,
        "network_integration": state.network_integration.as_str(),
        "daemon_version": state.daemon_version,
        "protocol_version": state.protocol_version,
    });
    if let Some(owner) = state.active_owner_uid {
        document["active_owner_uid"] = serde_json::json!(owner);
    }
    serde_json::to_string_pretty(&document).expect("status document serializes")
}

fn print_status_human(state: &DaemonState) {
    println!("State:                {}", state.vpn_state);
    println!(
        "Network integration:  {}",
        state.network_integration.as_str()
    );
    if let Some(owner) = state.active_owner_uid {
        println!("Connection owner UID: {owner}");
    }
    println!(
        "Daemon:               {} (protocol {})",
        state.daemon_version, state.protocol_version
    );
}

fn daemon(sub: &DaemonSub, socket: Option<&Path>) -> RunResult {
    match sub {
        DaemonSub::Start => {
            eprintln!(
                "protonwire: the daemon is started by its systemd unit (packaged in milestone 8); \
                 for development run `protonwire-daemon` directly"
            );
            std::process::exit(1);
        }
        DaemonSub::Stop => {
            let mut client = connect(socket)?;
            client.shutdown_daemon()
        }
        DaemonSub::Status => {
            let mut client = connect(socket)?;
            let nonce = client.ping()?;
            let state = client.state()?;
            println!(
                "daemon {} is alive (protocol {}, state {})",
                state.daemon_version, state.protocol_version, state.vpn_state
            );
            let _ = nonce;
            Ok(())
        }
    }
}

fn connect_command(
    socket: Option<&Path>,
    target: protonwire_frontend_api::ConnectTarget,
) -> RunResult {
    let mut client = connect(socket)?;
    client.connect_vpn(target)
}

/// Commands with declared-but-unimplemented surfaces.
fn planned(command: &Command) -> bool {
    !matches!(
        command,
        Command::Status { .. }
            | Command::Daemon { .. }
            | Command::Connect { .. }
            | Command::Disconnect
    )
}

fn command_name(command: &Command) -> String {
    match command {
        Command::Login => "login".into(),
        Command::Logout => "logout".into(),
        Command::Account => "account".into(),
        Command::Credentials { .. } => "credentials".into(),
        Command::Protocols => "protocols".into(),
        Command::Integration => "integration".into(),
        Command::ChangeServer => "change-server".into(),
        Command::Reconnect => "reconnect".into(),
        Command::Servers { .. } => "servers".into(),
        Command::Group => "group".into(),
        Command::Select { .. } => "select".into(),
        Command::Config => "config".into(),
        Command::Profile => "profile".into(),
        Command::Split => "split".into(),
        Command::Dns => "dns".into(),
        Command::Port => "port".into(),
        Command::Killswitch => "killswitch".into(),
        Command::Lan => "lan".into(),
        Command::Debug { .. } => "debug".into(),
        _ => unreachable!("implemented commands do not reach command_name"),
    }
}

fn planned_milestone(command: &Command) -> &'static str {
    match command {
        Command::Login | Command::Logout | Command::Account | Command::Credentials { .. } => {
            "milestone 2 — Muon authentication and credential stores"
        }
        Command::Servers { .. } | Command::Config => {
            "milestone 2 — server catalog and configuration overlays"
        }
        Command::Group | Command::Select { .. } => "milestone 3 — selection and groups",
        Command::Protocols => "milestone 4 — ProTUN engine",
        Command::Integration | Command::Killswitch | Command::Lan | Command::Dns => {
            "milestone 5 — Linux network control"
        }
        Command::ChangeServer | Command::Profile | Command::Port | Command::Debug { .. } => {
            "milestone 6 — official service parity"
        }
        Command::Split => "milestone 7 — split tunneling",
        _ => unreachable!("implemented commands do not reach planned_milestone"),
    }
}
