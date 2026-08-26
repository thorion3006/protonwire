//! Command tree (PRD 9.1–9.7) and dispatch.

use std::io::IsTerminal as _;
use std::path::Path;

use clap::Subcommand;
use protonwire_client::ClientError;
use protonwire_frontend_api::{
    DaemonState, PhysicalCountrySource, RpcError, RpcErrorCode, SelectionFeature,
    SelectionModifiers, SelectionProtocol,
};

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
    Account {
        /// Machine-readable JSON — the typed FR-7H snapshot
        /// serialized verbatim (PRD 9.1 automation surface).
        #[arg(long)]
        json: bool,
    },
    /// Credential storage management (Milestone 2).
    Credentials {
        #[command(subcommand)]
        sub: Option<CredentialsSub>,
    },
    /// List available protocols (Milestone 4).
    Protocols,
    /// Show or set the network integration adapter (Milestone 5).
    Integration,
    /// Connect to a server or group (Milestone 4 for the tunnel;
    /// `--dry-run` resolves and prints the selection now — Milestone 3).
    Connect {
        /// Target words, for example: fastest | country GB | server UK#42 |
        /// group proton:fastest-country (PRD 9.2).
        #[arg(value_name = "TARGET", required = true)]
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
        #[command(subcommand)]
        sub: Option<ServersSub>,
    },
    /// Connection groups: list and inspect the built-in catalog
    /// (Milestone 3; PRD 9.1/§7.3B).
    Group {
        #[command(subcommand)]
        sub: Option<GroupSub>,
    },
    /// Resolve a target without connecting (Milestone 3, PRD §7.3:
    /// `protonwire select fastest --dry-run --json`) — a pure read of
    /// the daemon's selection surface; never establishes a tunnel.
    Select {
        /// Target words, as on `connect` (fastest | country GB |
        /// server UK#42 | group proton:fastest-country | ...).
        #[arg(value_name = "TARGET", required = true)]
        target: Vec<String>,

        /// Ranking policy (official|balanced|load|latency; PRD 9.3).
        #[arg(long)]
        by: Option<String>,

        /// Explicit physical country (FR-23Q's first source).
        #[arg(long, value_name = "COUNTRY_CODE")]
        physical_country: Option<String>,

        /// Excluded country (repeatable; FR-21).
        #[arg(long = "exclude-country", value_name = "COUNTRY_CODE")]
        exclude_countries: Vec<String>,

        /// Excluded state or region (repeatable; FR-21A).
        #[arg(long = "exclude-state", value_name = "STATE_OR_REGION")]
        exclude_states: Vec<String>,

        /// Excluded city (repeatable; FR-21A).
        #[arg(long = "exclude-city", value_name = "CITY_NAME")]
        exclude_cities: Vec<String>,

        /// Excluded server name (repeatable; FR-21A).
        #[arg(long = "exclude-server", value_name = "SERVER_NAME")]
        exclude_servers: Vec<String>,

        /// Required feature (repeatable: p2p|tor|secure-core|streaming|
        /// ipv6|port-forwarding; T-4/FR-23H).
        #[arg(long, value_name = "FEATURE")]
        require: Vec<String>,

        /// Protocol constraint (wireguard-udp|wireguard-tcp|stealth;
        /// `smart` is the connection plane's, Milestone 4).
        #[arg(long)]
        protocol: Option<String>,

        /// Accepted and implied — `select` never connects (declared for
        /// script compatibility with `connect --dry-run`).
        #[arg(long)]
        dry_run: bool,

        /// Machine-readable output: the typed FR-23T result document
        /// serialized verbatim.
        #[arg(long)]
        json: bool,
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

/// `protonwire servers` subcommands (PRD 9.4 manual refresh examples).
#[derive(Debug, Subcommand)]
pub enum ServersSub {
    /// Force a catalog refresh (warned + confirmed; Milestone 2).
    Refresh {
        /// Skip the refresh confirmation prompt. The refresh-budget
        /// warning is still printed when the refresh lands (PRD ~791).
        #[arg(long)]
        yes: bool,
    },
}

/// `protonwire group` subcommands (PRD §7.3B examples).
#[derive(Debug, Subcommand)]
pub enum GroupSub {
    /// List the built-in connection groups with availability
    /// (FR-23S/U). No network request (FR-23R).
    List {
        /// Filter by origin (proton|protonwire).
        #[arg(long)]
        origin: Option<String>,
        /// Machine-readable output: the typed catalog verbatim.
        #[arg(long)]
        json: bool,
    },
    /// Show one group's full definition.
    Show {
        /// The stable namespaced group id.
        id: String,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
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
            // `--dry-run` is the M3 selection surface: resolve and
            // print, never connect. The remaining modifiers ride it
            // as selection constraints (--by ranks; --protocol
            // filters — with no tunnel, both are pure selection).
            if *dry_run {
                let target = ConnectTargetArgs::parse(target)?;
                let modifiers = SelectionModifiers {
                    by: by.clone(),
                    physical_country: None,
                    excluded_countries: Vec::new(),
                    excluded_states: Vec::new(),
                    excluded_cities: Vec::new(),
                    excluded_servers: Vec::new(),
                    required_features: Vec::new(),
                    optional_features: Vec::new(),
                    required_protocol: parse_protocol(protocol.as_deref())?,
                };
                return select_command(socket, target, modifiers, *json);
            }
            // Declared-but-unhonored modifiers must refuse rather than
            // be discarded: sending the unmodified target would
            // silently ignore them once Connect lands (M4).
            if let Some((flag, milestone)) = connect_modifier_refusal(by, protocol) {
                return Err(ClientError::Rpc(RpcError::new(
                    RpcErrorCode::NotImplemented,
                    format!(
                        "`connect {flag}` is not implemented in milestone 1 (planned: {milestone})"
                    ),
                )));
            }
            let target = ConnectTargetArgs::parse(target)?;
            connect_command(socket, target)
        }
        Command::Disconnect => {
            let mut client = connect(socket)?;
            client.disconnect_vpn()
        }
        // The M2 account/servers surface (Codex PR#4 round 2, P1: the
        // SDK methods existed but no first-party client dispatched to
        // them — `planned()` caught these commands first).
        Command::Servers { sub } => servers_command(socket, sub, no_input),
        Command::Account { json } => account_command(socket, *json),
        // The M3 U7 selection/groups surface: dispatched to the client
        // machinery, never the planned-refusal catch-all.
        Command::Select {
            target,
            by,
            physical_country,
            exclude_countries,
            exclude_states,
            exclude_cities,
            exclude_servers,
            require,
            protocol,
            dry_run: _,
            json,
        } => {
            let target = ConnectTargetArgs::parse(target)?;
            let modifiers = SelectionModifiers {
                by: by.clone(),
                physical_country: physical_country.clone(),
                excluded_countries: exclude_countries.clone(),
                excluded_states: exclude_states.clone(),
                excluded_cities: exclude_cities.clone(),
                excluded_servers: exclude_servers.clone(),
                required_features: parse_features(require)?,
                optional_features: Vec::new(),
                required_protocol: parse_protocol(protocol.as_deref())?,
            };
            select_command(socket, target, modifiers, *json)
        }
        Command::Group { sub } => group_command(socket, sub),
        Command::Logout => {
            let mut client = connect(socket)?;
            client.logout()
        }
        Command::Login => {
            let is_tty = std::io::stdin().is_terminal();
            login_with_inputs(socket, is_tty, &mut read_stdin_line)
        }
        Command::Credentials { sub } => match sub {
            None | Some(CredentialsSub::Status) => credentials_status(socket),
            // The writable-store operations are the S5c/post-M2 lane's.
            Some(_) => planned_refusal(command),
        },
        // Everything else is declared surface with an honest refusal.
        cmd if planned(cmd) => planned_refusal(cmd),
        _ => unreachable!("all commands are either implemented or planned"),
    }
}

/// One line from real stdin (the login/confirmation input seam; tests
/// inject their own reader).
fn read_stdin_line() -> std::io::Result<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// The declared-surface refusal in the module's house style.
fn planned_refusal(command: &Command) -> RunResult {
    Err(ClientError::Rpc(RpcError::new(
        RpcErrorCode::NotImplemented,
        format!(
            "`{}` is not implemented yet (planned: {})",
            command_name(command),
            planned_milestone(command),
        ),
    )))
}

/// `protonwire servers [refresh --yes]` — the cached catalog, and the
/// manual refresh with its warned+confirmed ceremony (FR-11/FR-13I).
fn servers_command(socket: Option<&Path>, sub: &Option<ServersSub>, no_input: bool) -> RunResult {
    use protonwire_frontend_api::{ConfirmationRequirement, RpcErrorCode};
    let mut client = connect(socket)?;
    match sub {
        None => {
            let protonwire_client::ServersSnapshot {
                etag,
                fetched_unix,
                body,
            } = client.servers_list()?;
            let document: serde_json::Value = body
                .as_deref()
                .and_then(|text| serde_json::from_str(text).ok())
                .unwrap_or(serde_json::Value::Null);
            let logicals = document
                .get("LogicalServers")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            println!("Servers:            {logicals} (cached catalog)");
            println!("ETag:               {}", etag.as_deref().unwrap_or("—"));
            println!(
                "Fetched (unix):     {}",
                fetched_unix.map_or("—".to_owned(), |t| t.to_string())
            );
            Ok(())
        }
        Some(ServersSub::Refresh { yes }) => match client.servers_refresh(None) {
            Ok(report) => refresh_report_result(&report),
            Err(ClientError::Rpc(rpc)) if rpc.code == RpcErrorCode::ConfirmationRequired => {
                let Some(requirement) = ConfirmationRequirement::from_error(&rpc) else {
                    return Err(ClientError::Rpc(rpc));
                };
                eprintln!("warning: {}", requirement.warning);
                eprintln!(
                    "  catalog age: {}s; next eligible at unix {}",
                    requirement.catalog_age_seconds, requirement.next_eligible_unix,
                );
                if !*yes {
                    if no_input {
                        return Err(ClientError::Rpc(RpcError::new(
                            RpcErrorCode::InvalidParams,
                            "an early refresh needs --yes (or an interactive confirm); \
                                 --no-input refuses the prompt",
                        )));
                    }
                    print!("Refresh now? [y/N] ");
                    use std::io::Write as _;
                    std::io::stdout().flush().ok();
                    let answer = read_stdin_line().unwrap_or_default();
                    if !answer.eq_ignore_ascii_case("y") {
                        println!("refresh declined");
                        return Ok(());
                    }
                }
                let report = client.servers_refresh(Some(&requirement.confirmation_token))?;
                refresh_report_result(&report)
            }
            Err(other) => Err(other),
        },
    }
}

/// Renders the report; an unsuccessful refresh (rate-limited or
/// failed) renders AND returns a typed error — scripts must distinguish
/// a refreshed catalog from an unsuccessful attempt by exit code
/// (Codex PR#4 round 3).
fn refresh_report_result(report: &protonwire_frontend_api::ServersRefreshReport) -> RunResult {
    use protonwire_frontend_api::ServersRefreshOutcome;
    print_refresh_report(report);
    match &report.outcome {
        ServersRefreshOutcome::Changed { .. } | ServersRefreshOutcome::NotModified => Ok(()),
        ServersRefreshOutcome::RateLimited { .. } => Err(ClientError::Rpc(RpcError::new(
            RpcErrorCode::RateLimited,
            "the upstream rate-limited the refresh; the suppression deadline governs the \
             next attempt",
        ))),
        ServersRefreshOutcome::Failed { reason } => Err(ClientError::Rpc(RpcError::new(
            RpcErrorCode::Internal,
            format!("the refresh failed: {reason}"),
        ))),
    }
}

fn print_refresh_report(report: &protonwire_frontend_api::ServersRefreshReport) {
    use protonwire_frontend_api::ServersRefreshOutcome;
    match &report.outcome {
        ServersRefreshOutcome::Changed { etag } => println!(
            "Refreshed:          new revision ({})",
            etag.as_deref().unwrap_or("no etag")
        ),
        ServersRefreshOutcome::NotModified => {
            println!("Refreshed:          catalog unchanged (304)")
        }
        ServersRefreshOutcome::RateLimited {
            retry_after_seconds,
        } => println!(
            "Refreshed:          rate-limited (Retry-After {:?}); suppressed until unix {:?}",
            retry_after_seconds, report.suppression_until_unix
        ),
        ServersRefreshOutcome::Failed { reason } => {
            println!("Refreshed:          FAILED — {reason}")
        }
    }
    println!("Next eligible:      {}", report.next_eligible_unix);
}

/// `protonwire account [--json]` — the FR-7H snapshot, human-rendered
/// or serialized verbatim (the automation contract: `--json` prints
/// the TYPED document, never a human rendering re-parsed).
fn account_command(socket: Option<&Path>, json: bool) -> RunResult {
    let mut client = connect(socket)?;
    let account = client.get_account()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&account).expect("the typed snapshot serializes")
        );
        return Ok(());
    }
    // The serde kebab/string forms are the display contract; the Debug
    // fallback covers a non-string serialization shape.
    let login_status = &account.login_status;
    println!(
        "Login status:       {}",
        serde_json::to_value(login_status)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{login_status:?}"))
    );
    let credential_source = &account.credential_source;
    println!(
        "Credential source:  {}",
        serde_json::to_value(credential_source)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{credential_source:?}"))
    );
    println!(
        "Writable store:     declared {}, priority {:?}",
        account.writable_store.declared, account.writable_store.priority
    );
    // Absence is the wire contract's UNKNOWN (not-yet-wired) — never
    // fabricated into a verdict (Codex PR#4 round 3).
    println!(
        "Persistence health: {}",
        account.persistence_health.as_ref().map_or_else(
            || "unknown (no writable store reporting)".to_owned(),
            |h| serde_json::to_string(h).unwrap_or_else(|_| format!("{h:?}"))
        )
    );
    Ok(())
}

/// `protonwire credentials` (status view): the credential facts of the
/// FR-7H snapshot.
fn credentials_status(socket: Option<&Path>) -> RunResult {
    account_command(socket, false)
}

// --- The M3 U7 selection/groups surface (§9.2/9.3/9.5, FR-23U) -------

/// Parses the `--require` feature vocabulary (T-4). Unknown values are
/// the typed InvalidParams refusal naming the vocabulary — never a
/// silent skip.
fn parse_features(values: &[String]) -> Result<Vec<SelectionFeature>, ClientError> {
    values
        .iter()
        .map(|value| match value.as_str() {
            "p2p" => Ok(SelectionFeature::P2p),
            "tor" => Ok(SelectionFeature::Tor),
            "secure-core" => Ok(SelectionFeature::SecureCore),
            "streaming" => Ok(SelectionFeature::Streaming),
            "ipv6" => Ok(SelectionFeature::Ipv6),
            "port-forwarding" => Ok(SelectionFeature::PortForwarding),
            other => Err(ClientError::Rpc(RpcError::new(
                RpcErrorCode::InvalidParams,
                format!(
                    "unknown feature `{other}`: expected p2p, tor, secure-core, streaming, \
                     ipv6, or port-forwarding"
                ),
            ))),
        })
        .collect()
}

/// Parses the `--protocol` selection constraint (§9.4's wireguard
/// family; `smart` is refused with guidance — smart-protocol resolution
/// is the connection plane's, Milestone 4).
fn parse_protocol(value: Option<&str>) -> Result<Option<SelectionProtocol>, ClientError> {
    match value {
        None => Ok(None),
        Some("wireguard-udp") => Ok(Some(SelectionProtocol::WireguardUdp)),
        Some("wireguard-tcp") => Ok(Some(SelectionProtocol::WireguardTcp)),
        Some("stealth") => Ok(Some(SelectionProtocol::Stealth)),
        Some("smart") => Err(ClientError::Rpc(RpcError::new(
            RpcErrorCode::InvalidParams,
            "`--protocol smart` resolves at connection time (milestone 4's smart-protocol \
             engine); a dry-run selection takes an explicit transport",
        ))),
        Some(other) => Err(ClientError::Rpc(RpcError::new(
            RpcErrorCode::InvalidParams,
            format!(
                "unknown protocol `{other}`: expected wireguard-udp, wireguard-tcp, or stealth"
            ),
        ))),
    }
}

/// `protonwire select <target> [modifiers]` and `connect --dry-run`:
/// the pure read of the daemon's selection surface (never a tunnel).
/// `--json` prints the TYPED FR-23T document verbatim (the automation
/// contract — a human rendering is never re-parsed).
fn select_command(
    socket: Option<&Path>,
    target: protonwire_frontend_api::ConnectTarget,
    modifiers: SelectionModifiers,
    json: bool,
) -> RunResult {
    let mut client = connect(socket)?;
    let result = client.select(target, modifiers)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&*result).expect("the typed result serializes")
        );
        return Ok(());
    }
    print_selection_human(&result);
    Ok(())
}

/// The human rendering: the winner first, then the FR-23T facts a
/// terminal user needs (policy + provenance, group identity, the
/// physical-country composition, and where every other candidate
/// went).
fn print_selection_human(result: &protonwire_frontend_api::SelectionResult) {
    println!(
        "Selected:           {} ({}, tier {})",
        result.winner.name, result.winner.exit_country, result.winner.tier
    );
    println!(
        "Policy:             {} ({})",
        result.selector.policy, result.winner.signals.provenance
    );
    match (
        result.winner.signals.proton_score,
        result.winner.signals.load,
    ) {
        (Some(score), Some(load)) => println!("Signals:            score {score:.2}, load {load}%"),
        (Some(score), None) => println!("Signals:            score {score:.2}"),
        (None, Some(load)) => println!("Signals:            load {load}%"),
        (None, None) => {}
    }
    if let Some(latency) = result.winner.signals.latency_ms {
        println!("Latency:            {latency} ms (bounded on-demand probe)");
    }
    if let Some(group) = &result.group {
        println!(
            "Group:              {} ({}, {})",
            group.group_id, group.origin, group.policy_provenance
        );
    }
    if let Some(physical) = &result.physical_country {
        println!(
            "Physical country:   {} ({})",
            physical.country,
            match physical.source {
                PhysicalCountrySource::ExplicitRequest => "explicit request",
                PhysicalCountrySource::Config => "config",
                PhysicalCountrySource::CachedLocation => "cached location",
            }
        );
    }
    let stages = result
        .hard_filters
        .stages
        .iter()
        .map(|stage| format!("{} {}", stage.eliminated, stage.stage))
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "Considered:         {} candidates, {} survivor(s){}",
        result.hard_filters.considered,
        result.hard_filters.survivors,
        if stages.is_empty() {
            String::new()
        } else {
            format!("; eliminated: {stages}")
        }
    );
    if !result.requested_features.is_empty() {
        println!(
            "Features:           [{}]",
            result.requested_features.join(", ")
        );
    }
    if !result.feature_difference.is_empty() {
        println!(
            "Feature difference: {}",
            result.feature_difference.join(", ")
        );
    }
}

/// `protonwire group [list|show]` (FR-23U): the registry-served
/// catalog with availability (FR-23S), or one group's definition.
fn group_command(socket: Option<&Path>, sub: &Option<GroupSub>) -> RunResult {
    let mut client = connect(socket)?;
    match sub {
        // The bare `protonwire group` is the list (PRD 9.1).
        None | Some(GroupSub::List { .. }) => {
            let (origin, json) = match sub {
                Some(GroupSub::List { origin, json }) => (origin.clone(), *json),
                _ => (None, false),
            };
            let catalog = client.groups_list()?;
            let groups: Vec<_> = catalog
                .groups
                .iter()
                .filter(|group| origin.as_ref().is_none_or(|wanted| &group.origin == wanted))
                .collect();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&catalog).expect("the typed catalog serializes")
                );
                return Ok(());
            }
            println!(
                "Groups:             {} built-in (registry {}, taxonomy {})",
                catalog.groups.len(),
                catalog.catalog_revision,
                catalog.taxonomy_revision
            );
            if let Some(wanted) = origin {
                println!("Origin filter:      {wanted}");
            }
            for group in groups {
                println!(
                    "  {:<38} {:<12} {:<28} {}",
                    group.id,
                    group.origin,
                    group.ranking_policy,
                    match (&group.availability.available, &group.availability.reason) {
                        (true, _) => "available".to_owned(),
                        (false, Some(reason)) => format!("unavailable ({reason})"),
                        (false, None) => "unavailable".to_owned(),
                    }
                );
            }
            Ok(())
        }
        Some(GroupSub::Show { id, json }) => {
            let details = client.group_show(id)?;
            if *json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&*details).expect("the typed details serialize")
                );
                return Ok(());
            }
            println!("Group:              {}", details.summary.id);
            println!("Label:              {}", details.summary.label);
            println!(
                "Origin:             {} (defined by {})",
                details.summary.origin, details.summary.definition_source
            );
            println!(
                "Policy:             {}{}",
                details.summary.ranking_policy,
                if details.summary.allowed_ranking_overrides.is_empty() {
                    String::new()
                } else {
                    format!(
                        " (overrides: {})",
                        details.summary.allowed_ranking_overrides.join(", ")
                    )
                }
            );
            println!(
                "Target:             {}{}",
                details.target,
                details
                    .target_detail
                    .as_ref()
                    .map_or_else(String::new, |detail| format!(" {detail}"))
            );
            if let Some(protocol) = &details.protocol_override {
                println!("Protocol override:  {protocol}");
            }
            for [key, value] in &details.connection_overrides {
                println!("Override:           {key} = {value} (composed at connect time)");
            }
            println!(
                "Availability:       {}",
                match (
                    &details.summary.availability.available,
                    &details.summary.availability.reason
                ) {
                    (true, _) => "available".to_owned(),
                    (false, Some(reason)) => format!("unavailable ({reason})"),
                    (false, None) => "unavailable".to_owned(),
                }
            );
            println!("Sources:            {}", details.sources.join(", "));
            Ok(())
        }
    }
}

/// `protonwire login` — interactive-source login over the SDK.
///
/// Credentials arrive on NON-TTY stdin only (piped/scripted use): a
/// terminal prompt would echo the password (no echo control in std,
/// and the rpassword dependency waits for the M8 frontend polish with
/// its own audit). On a TTY the command refuses with guidance —
/// fail-closed, never an echoed secret.
fn login_with_inputs(
    socket: Option<&Path>,
    is_tty: bool,
    read_line: &mut dyn FnMut() -> std::io::Result<String>,
) -> RunResult {
    use protonwire_frontend_api::LoginOutcome;
    if is_tty {
        return Err(ClientError::Rpc(RpcError::new(
            RpcErrorCode::InvalidParams,
            "login reads credentials from stdin (username, then password) when piped; a \
             terminal prompt would echo the password — pipe them, or use the credential \
             stores",
        )));
    }
    let read_err = |e: std::io::Error| {
        ClientError::Rpc(RpcError::new(RpcErrorCode::InvalidParams, e.to_string()))
    };
    let username = read_line().map_err(read_err)?;
    let password = read_line().map_err(read_err)?;
    let mut client = connect(socket)?;
    match client.begin_login(username, password)? {
        LoginOutcome::Session { user_id, .. } => {
            println!("Signed in as {user_id}.");
            Ok(())
        }
        LoginOutcome::Challenge { totp_enabled, .. } => {
            if !totp_enabled {
                return Err(ClientError::Rpc(RpcError::new(
                    RpcErrorCode::UnsupportedChallenge,
                    "the account requires a second factor this build cannot supply \
                     non-interactively",
                )));
            }
            print!("Two-factor code: ");
            use std::io::Write as _;
            std::io::stdout().flush().ok();
            let code = read_line().map_err(read_err)?;
            match client.submit_two_factor(code)? {
                LoginOutcome::Session { user_id, .. } => {
                    println!("Signed in as {user_id}.");
                    Ok(())
                }
                other => Err(ClientError::Rpc(RpcError::new(
                    RpcErrorCode::InvalidParams,
                    format!("login did not complete: {other:?}"),
                ))),
            }
        }
        LoginOutcome::Blocked { reason } => Err(ClientError::Rpc(RpcError::new(
            RpcErrorCode::UpstreamCapabilityBlocked,
            format!("{reason:?}"),
        ))),
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
        DaemonSub::Start => Err(ClientError::Rpc(RpcError::new(
            RpcErrorCode::NotImplemented,
            "the daemon is started by its systemd unit (packaged in milestone 8); \
             for development run `protonwire-daemon` directly",
        ))),
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

/// The first unimplemented connect modifier, with its planned milestone
/// in the module's refusal style (`--dry-run` no longer appears — the
/// M3 surface resolves it; `--by` without `--dry-run` waits for the M4
/// tunnel's connect-time composition, as does `--protocol`).
fn connect_modifier_refusal(
    by: &Option<String>,
    protocol: &Option<String>,
) -> Option<(&'static str, &'static str)> {
    if by.is_some() {
        Some((
            "--by",
            "milestone 4 — selection composes at connect time with the ProTUN engine",
        ))
    } else if protocol.is_some() {
        Some(("--protocol", "milestone 4 — ProTUN engine"))
    } else {
        None
    }
}

/// Commands with declared-but-unimplemented surfaces.
fn planned(command: &Command) -> bool {
    matches!(
        command,
        Command::Protocols
            | Command::Integration
            | Command::ChangeServer
            | Command::Reconnect
            | Command::Config
            | Command::Profile
            | Command::Split
            | Command::Dns
            | Command::Port
            | Command::Killswitch
            | Command::Lan
            | Command::Debug { .. }
            // The writable-store operations (S5c's brokered lane).
            | Command::Credentials {
                sub: Some(
                    CredentialsSub::Migrate { .. }
                    | CredentialsSub::ImportProvisionedSession { .. }
                    | CredentialsSub::ForgetPassword
                ),
            }
    )
}

fn command_name(command: &Command) -> String {
    match command {
        Command::Login => "login".into(),
        Command::Logout => "logout".into(),
        Command::Account { .. } => "account".into(),
        Command::Credentials { .. } => "credentials".into(),
        Command::Protocols => "protocols".into(),
        Command::Integration => "integration".into(),
        Command::ChangeServer => "change-server".into(),
        Command::Reconnect => "reconnect".into(),
        Command::Servers { sub: None } => "servers".into(),
        Command::Servers {
            sub: Some(ServersSub::Refresh { .. }),
        } => "servers refresh".into(),
        Command::Group { sub: None }
        | Command::Group {
            sub: Some(GroupSub::List { .. }),
        } => "group list".into(),
        Command::Group {
            sub: Some(GroupSub::Show { .. }),
        } => "group show".into(),
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
        Command::Credentials { .. } | Command::Config => {
            "the post-M2 writable-store and overlay lanes"
        }
        Command::Protocols | Command::Reconnect => "milestone 4 — ProTUN engine",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_json_shape_matches_prd_118_subset() {
        let state = DaemonState {
            protocol_version: 1,
            daemon_version: "0.1.0".into(),
            vpn_state: protonwire_frontend_api::VpnState::Disconnected,
            network_integration: protonwire_frontend_api::NetworkIntegration::Auto,
            active_owner_uid: None,
            latest_event_seq: None,
        };
        let document: serde_json::Value = serde_json::from_str(&status_json(&state)).unwrap();
        assert_eq!(document["state"], "disconnected");
        assert_eq!(document["network_integration"], "auto");
        assert_eq!(document["daemon_version"], "0.1.0");
        assert_eq!(document["protocol_version"], 1);
        assert!(document.get("active_owner_uid").is_none());

        let owned = DaemonState {
            active_owner_uid: Some(1000),
            ..state
        };
        let document: serde_json::Value = serde_json::from_str(&status_json(&owned)).unwrap();
        assert_eq!(document["active_owner_uid"], 1000);
    }

    /// The dispatch contract: `run` returns errors; it never exits the
    /// process. `daemon start` must be an error like every other refusal
    /// (red phase observed as the whole test binary exiting 1).
    #[test]
    fn daemon_start_returns_error_instead_of_exiting() {
        let err = run(
            &Command::Daemon {
                sub: DaemonSub::Start,
            },
            None,
            true,
        )
        .expect_err("daemon start must return an error, not exit");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("systemd unit"));
    }

    #[test]
    fn planned_commands_return_typed_refusals() {
        // Login/Logout/Account/Servers dispatch for real now (the M2
        // surface); the refusal contract is pinned on a still-planned
        // command.
        let err = run(&Command::Protocols, None, true).expect_err("refusal");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("milestone 4"));
    }

    /// The M2 dispatch (Codex PR#4 round 2, P1): login/logout/account/
    /// servers reach the CLIENT, not the planned-refusal catch-all.
    /// Without a daemon the dispatch ends in the SDK's typed
    /// connection error — proving the arm routes to the client
    /// machinery instead of the declared-surface refusal.
    #[test]
    fn the_m2_commands_dispatch_to_the_client_not_the_refusal() {
        for command in [
            Command::Logout,
            Command::Account { json: false },
            Command::Servers { sub: None },
            Command::Servers {
                sub: Some(ServersSub::Refresh { yes: true }),
            },
            Command::Credentials { sub: None },
        ] {
            let err = run(&command, None, true).expect_err("no daemon is listening");
            assert_ne!(
                err.exit_code(),
                1,
                "`{err}` must not be the planned-refusal exit; the dispatch reaches the client",
            );
            assert!(
                !err.to_string().contains("planned"),
                "the M2 commands are implemented, not planned: {err}"
            );
        }
    }

    /// Login on a TTY refuses BEFORE any connection or credential
    /// reading: a terminal prompt would echo the password (no echo
    /// control in std; the rpassword dependency rides the M8 audit) —
    /// fail-closed with piped-credential guidance.
    #[test]
    fn login_on_a_tty_refuses_rather_than_echo_the_password() {
        let err = login_with_inputs(None, true, &mut || unimplemented!("never read on a tty"))
            .expect_err("the tty gate refuses before reading");
        assert!(err.to_string().contains("pipe"), "guidance: {err}");
        assert!(err.to_string().contains("echo"), "names the hazard: {err}");
    }

    /// Login with piped inputs drives the full SDK flow (the reader
    /// seam): username, password, and — on a TOTP challenge — the
    /// code line. Without a daemon the flow ends in the typed
    /// connection error, AFTER the inputs were consumed.
    #[test]
    fn login_with_piped_inputs_consumes_credentials_and_reaches_the_client() {
        let lines = std::cell::Cell::new(0u32);
        let mut reader = || {
            lines.set(lines.get() + 1);
            Ok::<_, std::io::Error>("value".to_owned())
        };
        let err = login_with_inputs(None, false, &mut reader).expect_err("no daemon");
        assert_eq!(lines.get(), 2, "username and password were read");
        assert_ne!(err.exit_code(), 1, "not the planned refusal: {err}");
    }

    /// Review-fix V2's discipline, post-M3: `--by`/`--protocol` WITHOUT
    /// `--dry-run` still refuse with their planned milestone (the M4
    /// tunnel composes them at connect time) — a modifier may never be
    /// silently discarded. `--dry-run` no longer appears here: it IS
    /// the M3 surface (see connect_dry_run_dispatches_to_the_selection).
    #[test]
    fn connect_modifier_flags_are_refused_with_their_milestones() {
        let fastest = || vec!["fastest".to_string()];
        let cases = [
            (
                Command::Connect {
                    target: fastest(),
                    by: Some("latency".into()),
                    protocol: None,
                    dry_run: false,
                    json: false,
                },
                "--by",
                "milestone 4",
            ),
            (
                Command::Connect {
                    target: fastest(),
                    by: None,
                    protocol: Some("stealth".into()),
                    dry_run: false,
                    json: false,
                },
                "--protocol",
                "milestone 4",
            ),
        ];
        for (command, flag, milestone) in cases {
            let err = run(&command, None, true)
                .expect_err("an unimplemented connect modifier must refuse");
            assert_eq!(err.exit_code(), 1, "NotImplemented exit code");
            let message = err.to_string();
            assert!(message.contains(flag), "must name the flag: {message}");
            assert!(
                message.contains(milestone),
                "must name the planned milestone: {message}"
            );
        }
    }

    /// The M3 U7 dispatch: `select`, `group`, and `connect --dry-run`
    /// reach the CLIENT machinery (the SDK's select/groups wrappers),
    /// never the planned-refusal catch-all. Without a daemon the
    /// dispatch ends in the typed connection error — the proof the arm
    /// routed past every gate (the FU-4 hermetic-socket idiom).
    #[test]
    fn the_u7_surface_dispatches_to_the_client() {
        let socket =
            std::env::temp_dir().join(format!("protonwire-cli-u7-{}.sock", std::process::id()));
        let cases = vec![
            Command::Select {
                target: vec!["country".to_string(), "GB".to_string()],
                by: Some("latency".into()),
                physical_country: Some("DE".into()),
                exclude_countries: vec!["US".into()],
                exclude_states: Vec::new(),
                exclude_cities: Vec::new(),
                exclude_servers: Vec::new(),
                require: vec!["port-forwarding".into()],
                protocol: Some("stealth".into()),
                dry_run: true,
                json: true,
            },
            Command::Group { sub: None },
            Command::Group {
                sub: Some(GroupSub::List {
                    origin: Some("proton".into()),
                    json: false,
                }),
            },
            Command::Group {
                sub: Some(GroupSub::Show {
                    id: "proton:fastest-country".into(),
                    json: true,
                }),
            },
            Command::Connect {
                target: vec!["fastest".to_string()],
                by: Some("load".into()),
                protocol: None,
                dry_run: true,
                json: false,
            },
        ];
        for command in cases {
            match run(&command, Some(&socket), true) {
                // The socket cannot exist: DaemonUnavailable IS the
                // dispatch proof — the request got past every refusal
                // gate and attempted the daemon.
                Err(ClientError::DaemonUnavailable(_)) => {}
                other => panic!(
                    "the U7 commands must dispatch to the client, got {other:?} \
                     for {command:?}"
                ),
            }
        }
    }

    /// The vocabulary gates: unknown `--require` features and unknown
    /// or `smart` `--protocol` values are typed InvalidParams (2)
    /// refusals naming the vocabulary — never a silent skip, and
    /// BEFORE any daemon connection is attempted.
    #[test]
    fn u7_vocabulary_refusals_are_typed_and_pre_connection() {
        let socket = std::env::temp_dir().join(format!(
            "protonwire-cli-u7-vocab-{}.sock",
            std::process::id()
        ));
        for (require, protocol, needle) in [
            (vec!["wifi".to_string()], None, "unknown feature `wifi`"),
            (
                Vec::new(),
                Some("quic".to_string()),
                "unknown protocol `quic`",
            ),
            (Vec::new(), Some("smart".to_string()), "connection time"),
        ] {
            let command = Command::Select {
                target: vec!["fastest".to_string()],
                by: None,
                physical_country: None,
                exclude_countries: Vec::new(),
                exclude_states: Vec::new(),
                exclude_cities: Vec::new(),
                exclude_servers: Vec::new(),
                require,
                protocol,
                dry_run: false,
                json: false,
            };
            let err =
                run(&command, Some(&socket), true).expect_err("the vocabulary gate must refuse");
            assert_eq!(err.exit_code(), 2, "InvalidParams exit code: {err}");
            assert!(err.to_string().contains(needle), "{err}");
        }
    }

    /// Bare `connect <target>`, and `--json` alone (presentation-only, so it
    /// stays ignored rather than refused), must keep dispatching: the
    /// modifier gate may not fire without a modifier, so the request still
    /// reaches the daemon.
    ///
    /// FU-4 (rust-review round-5 follow-up, Low): the socket is a path
    /// that cannot exist (an explicit `Some(path)` also wins over
    /// PROTONWIRE_SOCKET and the /run/protonwire default), so only the
    /// DaemonUnavailable branch is reachable — previously `None` fell
    /// back to the default socket, and a live dev daemon from another
    /// build made this assertion read whatever that build answered.
    #[test]
    fn bare_connect_and_json_only_still_dispatch() {
        let socket = std::env::temp_dir().join(format!(
            "protonwire-cli-nonexistent-{}.sock",
            std::process::id()
        ));
        for command in [
            Command::Connect {
                target: vec!["fastest".into()],
                by: None,
                protocol: None,
                dry_run: false,
                json: false,
            },
            Command::Connect {
                target: vec!["fastest".into()],
                by: None,
                protocol: None,
                dry_run: false,
                json: true,
            },
        ] {
            match run(&command, Some(&socket), true) {
                // The socket cannot exist: DaemonUnavailable IS the
                // dispatch proof — the request got past the modifier gate
                // and attempted the daemon.
                Err(ClientError::DaemonUnavailable(_)) => {}
                other => panic!("bare connect must still dispatch, got {other:?}"),
            }
        }
    }

    /// The `protonwire servers [refresh --yes]` dispatch reaches the
    /// CLIENT now (the M2 surface; Codex PR#4 round 2): without a
    /// daemon, the typed connection error — never the planned refusal,
    /// and never a clap panic (the subcommand fix this test's ancestor
    /// guarded).
    #[test]
    fn servers_commands_dispatch_to_the_client() {
        for yes in [false, true] {
            let err = run(
                &Command::Servers {
                    sub: Some(ServersSub::Refresh { yes }),
                },
                None,
                true,
            )
            .expect_err("no daemon is listening");
            assert_ne!(err.exit_code(), 1, "not the planned refusal: {err}");
            assert!(!err.to_string().contains("planned"), "dispatched: {err}");
        }

        let err =
            run(&Command::Servers { sub: None }, None, true).expect_err("no daemon is listening");
        assert!(!err.to_string().contains("planned"), "dispatched: {err}");
    }

    /// Round 7 (Zj_QN) — the class killer: EVERY `Command` variant must
    /// survive `run()` without panicking. `protonwire reconnect` panicked
    /// because `planned()` routed it into the typed-refusal path while
    /// `planned_milestone` had no arm for it (`_ => unreachable!()`), and
    /// `protonwire servers refresh` panicked the same shape before the
    /// round-4 subcommand fix. Per-variant refusal tests only cover the
    /// variants someone thought to test; this walks the whole enum. The
    /// socket is a path that cannot exist, so each dispatch reaches only
    /// its refusal or DaemonUnavailable branch — any `unreachable!()`,
    /// missing match arm, or unwrap on the dispatch path fails here.
    ///
    /// `assert_every_variant_listed` is the exhaustiveness half: it has no
    /// wildcard arm, so ADDING a `Command` variant without extending this
    /// test's table breaks compilation rather than silently skipping it.
    #[test]
    fn every_command_survives_dispatch_without_panicking() {
        use std::panic::AssertUnwindSafe;

        fn assert_every_variant_listed(command: &Command) {
            match command {
                Command::Login
                | Command::Logout
                | Command::Account { .. }
                | Command::Credentials { .. }
                | Command::Protocols
                | Command::Integration
                | Command::Connect { .. }
                | Command::ChangeServer
                | Command::Disconnect
                | Command::Reconnect
                | Command::Status { .. }
                | Command::Servers { .. }
                | Command::Group { .. }
                | Command::Select { .. }
                | Command::Config
                | Command::Profile
                | Command::Split
                | Command::Dns
                | Command::Port
                | Command::Killswitch
                | Command::Lan
                | Command::Daemon { .. }
                | Command::Debug { .. } => {}
            }
        }

        let socket = std::env::temp_dir().join(format!(
            "protonwire-cli-dispatch-meta-{}.sock",
            std::process::id()
        ));
        let cases: Vec<(&str, Command)> = vec![
            ("login", Command::Login),
            ("logout", Command::Logout),
            ("account", Command::Account { json: false }),
            ("credentials", Command::Credentials { sub: None }),
            ("protocols", Command::Protocols),
            ("integration", Command::Integration),
            (
                "connect",
                Command::Connect {
                    target: vec!["fastest".to_string()],
                    by: None,
                    protocol: None,
                    dry_run: false,
                    json: false,
                },
            ),
            ("change-server", Command::ChangeServer),
            ("disconnect", Command::Disconnect),
            ("reconnect", Command::Reconnect),
            ("status", Command::Status { json: false }),
            ("servers", Command::Servers { sub: None }),
            ("group list (bare)", Command::Group { sub: None }),
            (
                "group list",
                Command::Group {
                    sub: Some(GroupSub::List {
                        origin: None,
                        json: false,
                    }),
                },
            ),
            (
                "group show",
                Command::Group {
                    sub: Some(GroupSub::Show {
                        id: "proton:fastest-country".into(),
                        json: false,
                    }),
                },
            ),
            (
                "select",
                Command::Select {
                    target: vec!["fastest".to_string()],
                    by: None,
                    physical_country: None,
                    exclude_countries: Vec::new(),
                    exclude_states: Vec::new(),
                    exclude_cities: Vec::new(),
                    exclude_servers: Vec::new(),
                    require: Vec::new(),
                    protocol: None,
                    dry_run: false,
                    json: false,
                },
            ),
            ("config", Command::Config),
            ("profile", Command::Profile),
            ("split", Command::Split),
            ("dns", Command::Dns),
            ("port", Command::Port),
            ("killswitch", Command::Killswitch),
            ("lan", Command::Lan),
            (
                "daemon",
                Command::Daemon {
                    sub: DaemonSub::Start,
                },
            ),
            ("debug", Command::Debug { sub: None }),
        ];
        assert_every_variant_listed(&cases[0].1);
        for (name, command) in cases {
            let outcome =
                std::panic::catch_unwind(AssertUnwindSafe(|| run(&command, Some(&socket), true)));
            assert!(
                outcome.is_ok(),
                "command `{name}` panicked during dispatch — a refusal or \
                 DaemonUnavailable was required, never a panic"
            );
        }
    }
}
