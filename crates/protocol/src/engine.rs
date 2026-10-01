//! The connection engine (M4 PR-4): composes PR-1's translation,
//! PR-2's persistent cache, and PR-3's TUN handle + mark seam into a
//! ProTUN `Connection` behind ProtonWire-owned types (PRD 6.5 rule 8,
//! FR-23E's connection-plane composition).
//!
//! One [`ConnectionEngine::connect`] call performs the whole
//! connection-plane setup: translate the candidate peers (FR-27),
//! compose the connection mode (production = LocalAgent over the
//! encrypted cache, FR-32A; deterministic tests = NoLocalAgent with an
//! explicit key), create and hand off the TUN descriptor (FR-24),
//! wire the FR-32B mark callback, and spawn the connection with
//! non-blocking state/event forwarding (FR-32D).
//!
//! All ProTUN types stop here: the public surface speaks engine
//! mirrors ([`EngineVpnState`], [`EngineEvent`], …) so an upstream
//! beta API change stays localized to `translate_state`/
//! `translate_event` and the map helpers.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use protun::api::connection::{
    Connection, ConnectionMode, ConnectivityEvent, MuonEnv, PersistentCache,
};
use protun::api::events::{ErrorEvent, Event, LocalAgentSettingType};
use protun::api::local_agent::{AgentConnectionInfo, LocalAgentSettings, NetshieldLevel};
use protun::api::state::{ConnectionState, InterfaceState, PeerConnectionInfo, Protocol, VpnState};

use crate::marks::{MarkHealth, MarkingFdCallback, SoMarkApplier};
use crate::reconcile::FeatureReconciliation;
use crate::translate::{KeyPolicy, translate_with_policy};
use crate::tun::{TunError, TunHandle};
use crate::{ProtocolError, TunnelParams};

// ---------------------------------------------------------------------------
// Engine mirror types (the public surface; no ProTUN leak)
// ---------------------------------------------------------------------------

/// Netshield level, engine-mirrored (ProTUN's four levels, 1:1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EngineNetshield {
    /// Netshield disabled.
    #[default]
    None,
    /// Malware filtering.
    MalwareFilter,
    /// Ads, trackers, and malware.
    AdsAndMalwareFilter,
    /// Adult content on top of ads/trackers/malware.
    AdultAndAdsAndMalwareFilter,
}

/// The LocalAgent feature request, engine-mirrored. `None` fields are
/// "no preference" — they cannot diverge and are never reported as
/// active (T-20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EngineAgentSettings {
    /// VPN Accelerator (split TCP).
    pub split_tcp: Option<bool>,
    /// The requested Netshield level.
    pub netshield_level: Option<EngineNetshield>,
    /// Safe mode (soft jail).
    pub soft_jail: Option<bool>,
    /// NAT-PMP port forwarding.
    pub port_forwarding: Option<bool>,
    /// Moderate NAT.
    pub random_nat: Option<bool>,
    /// Censorship circumvention routing (FR-32J).
    pub circumvention_routing: Option<bool>,
}

/// One LocalAgent setting identity. The six protun-refusable
/// settings plus the engine-side circumvention identity (FR-32J:
/// protun's refusal vocabulary has no circumvention variant, so the
/// divergence table is that setting's only honest-reporting surface).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineSettingType {
    /// Netshield level.
    Netshield,
    /// Secure-Core bounce.
    Bouncing,
    /// NAT-PMP port forwarding.
    PortForwarding,
    /// VPN Accelerator.
    SplitTcp,
    /// Safe mode.
    SafeMode,
    /// Moderate NAT.
    RandomNat,
    /// Censorship circumvention routing (never arrives as a protun
    /// refusal — divergence-table only).
    CircumventionRouting,
}

/// The Muon environment the LocalAgent session runs against,
/// engine-mirrored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineMuonEnv {
    /// Production.
    Prod,
    /// Atlas test environment.
    Atlas {
        /// The scientist branch, if any.
        scientist: Option<String>,
    },
    /// Custom server URLs.
    CustomServers {
        /// The base URLs.
        servers: Vec<String>,
    },
}

/// The connection mode the engine composes (FR-32A: production runs
/// LocalAgent over the encrypted cache; deterministic tests run
/// agent-less with an explicit key).
#[derive(Debug, Clone)]
pub enum EngineMode {
    /// Production: the LocalAgent session (certificate, feature
    /// negotiation) over the encrypted persistent cache — the WG key
    /// comes from the cache (ProTUN reads or generates it there).
    LocalAgent {
        /// The client's HTTP user agent.
        user_agent: String,
        /// The client's app version.
        app_version: String,
        /// The Muon environment.
        muon_env: EngineMuonEnv,
        /// The requested feature set (T-20's requested side).
        settings: EngineAgentSettings,
    },
    /// Deterministic tests: no agent session; the WG key is the
    /// explicit `client_private_key` of the tunnel params.
    NoLocalAgent,
}

/// The engine's static configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// The TUN interface name (FR-25 default `protonwire0`, FR-26
    /// configurable).
    pub if_name: String,
    /// The FR-32B stable bypass mark applied to every outer socket.
    pub bypass_mark: u32,
    /// The connection mode (production vs deterministic tests).
    ///
    /// Deliberately NO `Default`: the mode is a trust-relevant
    /// choice (production LocalAgent vs agent-less tests) - a
    /// caller that forgets it should fail to compile, not
    /// silently get the test engine.
    pub mode: EngineMode,
}

/// The transport actually in use for a peer (a live connection is
/// never `Smart` — Smart is the request; this is the answer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineTransport {
    /// WireGuard over UDP.
    WireGuardUdp,
    /// WireGuard over TCP.
    WireGuardTcp,
    /// Stealth (TLS).
    Stealth,
}

/// The peer a state event names, engine-mirrored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnginePeerRef {
    /// The caller's peer id (from `PeerParams.id`).
    pub peer_id: String,
    /// The entry address ProTUN is using.
    pub entry_ip: IpAddr,
    /// The transport in use.
    pub protocol: EngineTransport,
    /// The port in use.
    pub port: u16,
}

/// A server-side restriction, engine-mirrored (FR-123).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineRestriction {
    /// Streaming restricted; the server's reason string.
    Streaming {
        /// The server's reason.
        reason: String,
    },
    /// Torrenting restricted; the server's reason string.
    Torrent {
        /// The server's reason.
        reason: String,
    },
    /// Any other restriction.
    Other {
        /// The restriction's name.
        name: String,
        /// The server's reason.
        reason: String,
    },
}

/// What the LocalAgent reported about the connection, engine-mirrored
/// (the applied-settings side of T-20, plus the report fields the PRD
/// makes normative: groups FR-32DA, MTU + restrictions + exit IPs at
/// PRD line 468/FR-123. The ISP-identity fields are deliberately NOT
/// mirrored — no clause needs them at the engine surface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineAgentInfo {
    /// The server's exit IPv4.
    pub server_exit_v4: Option<IpAddr>,
    /// The server's exit IPv6.
    pub server_exit_v6: Option<IpAddr>,
    /// The server-probed MTU, if any (FR-27: applied after
    /// connection, never an address source).
    pub server_mtu: Option<u16>,
    /// LocalAgent-provided connection labels (FR-32DA: labels only —
    /// never connection-group catalog definitions).
    pub groups: Vec<String>,
    /// The server's restrictions (FR-7M/FR-123 surfaces them).
    pub restrictions: Vec<EngineRestriction>,
    /// The settings the server APPLIED (may differ from the request).
    pub applied: EngineAgentSettings,
}

/// Why the LocalAgent session is waiting (FR-7M: jail states — low
/// plan, disabled user, pending invoice, session over limit, VPN
/// 2FA… — must surface to the user).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineAgentWait {
    /// Soft-jailed: features restricted until resolved.
    SoftJailed,
    /// Hard-jailed: one jail entry per reason the server gave.
    HardJailed {
        /// The server's jail entries.
        jails: Vec<EngineAgentJail>,
    },
}

/// One hard-jail entry, engine-mirrored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineAgentJail {
    /// The jail category.
    pub reason: EngineJailReason,
    /// The server's numeric code.
    pub code: u64,
    /// The server's message (an untrusted display string).
    pub message: String,
}

/// The jail category, engine-mirrored 1:1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineJailReason {
    /// Bad user behavior.
    BadUserBehavior,
    /// The user is disabled.
    DisabledUser,
    /// The plan tier is too low.
    LowPlan,
    /// VPN 2FA is required.
    Need2FA,
    /// An invoice is pending.
    PendingInvoice,
    /// Too many simultaneous sessions.
    SessionOverLimit,
    /// The server waits for a client-challenge reply.
    WaitingClientChallengeReply,
    /// An internal server-side jail.
    Internal,
    /// Any other jail reason.
    Other,
}

/// The connection state machine, engine-mirrored (FR-29's raw
/// material; the daemon lane shapes it for the frontend).
#[derive(Debug, Clone, PartialEq)]
pub enum EngineConnectionState {
    /// Down; the string is the disconnect error, if any.
    Disconnected {
        /// The error that took the connection down, if any.
        error: Option<String>,
    },
    /// Cycling candidate peers.
    Connecting {
        /// The ids of the peers ProTUN is attempting.
        peer_ids: Vec<String>,
        /// Whether ProTUN is waiting for the OS to report network.
        waiting_for_network: bool,
    },
    /// WG up, LocalAgent session negotiating (the wait/jail reason
    /// surfaces — FR-7M).
    ConnectingToAgent {
        /// The peer whose tunnel carries the agent session.
        peer_id: String,
        /// Why the session is waiting, if reported.
        wait: Option<EngineAgentWait>,
    },
    /// Fully connected (in agent mode: WG + agent both up).
    Connected {
        /// The serving peer.
        peer: EnginePeerRef,
        /// The agent's report (absent in agent-less mode).
        agent: Option<EngineAgentInfo>,
    },
}

/// One VPN state snapshot, engine-mirrored.
#[derive(Debug, Clone, PartialEq)]
pub struct EngineVpnState {
    /// Whether the TUN interface is up.
    pub interface_up: bool,
    /// The interface error, if any (up or down).
    pub interface_error: Option<String>,
    /// The connection state.
    pub connection: EngineConnectionState,
}

/// Connection statistics (FR-30's raw material).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EngineStats {
    /// Bytes received.
    pub received_bytes: u64,
    /// Bytes sent.
    pub sent_bytes: u64,
    /// Time since the last WireGuard handshake.
    pub time_since_last_handshake: Duration,
    /// Estimated loss ratio.
    pub estimated_loss: f32,
    /// Estimated round-trip time.
    pub estimated_round_trip_time: Duration,
}

/// LocalAgent statistics, engine-mirrored (`None` = the server did
/// not report the counter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EngineAgentStats {
    /// Bytes received through the agent.
    pub bytes_received: Option<u64>,
    /// Bytes sent through the agent.
    pub bytes_sent: Option<u64>,
    /// Malicious requests blocked.
    pub malicious_blocked: Option<u64>,
    /// Ads blocked.
    pub ads_blocked: Option<u64>,
    /// Trackers blocked.
    pub trackers_blocked: Option<u64>,
    /// Adult content blocked.
    pub adult_content_blocked: Option<u64>,
    /// Estimated data saved.
    pub data_saved: Option<u64>,
}

/// The API endpoint an agent error names, engine-mirrored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineApiEndpoint {
    /// The Muon auth endpoint.
    Auth,
    /// The certificate refresh endpoint.
    CertificateRefresh,
}

/// Everything the engine forwards off ProTUN's connection thread
/// (FR-32D: the callbacks only translate and send — no blocking work
/// — and the daemon drains at its own pace).
#[derive(Debug, Clone, PartialEq)]
pub enum EngineEvent {
    /// A VPN state change.
    State(EngineVpnState),
    /// WireGuard connection statistics.
    Stats(EngineStats),
    /// LocalAgent statistics.
    AgentStats(EngineAgentStats),
    /// The server refused a requested setting outright.
    SettingRefused(EngineSettingType),
    /// The agent session needs a new API fork selector.
    ForkSelectorNeeded,
    /// Certificate refresh failed terminally — the caller should
    /// close the connection.
    CertificateFatal,
    /// An agent-side API call failed.
    ApiError {
        /// The endpoint that failed.
        endpoint: EngineApiEndpoint,
        /// The HTTP status, if any.
        http_code: Option<u16>,
        /// Whether the refresh token is invalid (a fork selector will
        /// not help).
        refresh_token_invalid: bool,
    },
}

// ---------------------------------------------------------------------------
// Translation helpers (pure; the seam every upstream change hits)
// ---------------------------------------------------------------------------

/// Translates one ProTUN netshield level (1:1).
pub fn netshield_to_protun(level: EngineNetshield) -> NetshieldLevel {
    match level {
        EngineNetshield::None => NetshieldLevel::None,
        EngineNetshield::MalwareFilter => NetshieldLevel::MalwareFilter,
        EngineNetshield::AdsAndMalwareFilter => NetshieldLevel::AdsAndMalwareFilter,
        EngineNetshield::AdultAndAdsAndMalwareFilter => NetshieldLevel::AdultAndAdsAndMalwareFilter,
    }
}

/// Translates one ProTUN netshield level back (1:1).
pub fn netshield_from_protun(level: NetshieldLevel) -> EngineNetshield {
    match level {
        NetshieldLevel::None => EngineNetshield::None,
        NetshieldLevel::MalwareFilter => EngineNetshield::MalwareFilter,
        NetshieldLevel::AdsAndMalwareFilter => EngineNetshield::AdsAndMalwareFilter,
        NetshieldLevel::AdultAndAdsAndMalwareFilter => EngineNetshield::AdultAndAdsAndMalwareFilter,
    }
}

/// Translates the engine feature request into ProTUN's.
pub fn settings_to_protun(settings: EngineAgentSettings) -> LocalAgentSettings {
    LocalAgentSettings {
        split_tcp: settings.split_tcp,
        netshield_level: settings.netshield_level.map(netshield_to_protun),
        soft_jail: settings.soft_jail,
        port_forwarding: settings.port_forwarding,
        random_nat: settings.random_nat,
        circumvention_routing: settings.circumvention_routing,
    }
}

/// Translates ProTUN's applied feature set back into the engine
/// mirror (T-20's applied side).
pub fn settings_from_protun(settings: LocalAgentSettings) -> EngineAgentSettings {
    EngineAgentSettings {
        split_tcp: settings.split_tcp,
        netshield_level: settings.netshield_level.map(netshield_from_protun),
        soft_jail: settings.soft_jail,
        port_forwarding: settings.port_forwarding,
        random_nat: settings.random_nat,
        circumvention_routing: settings.circumvention_routing,
    }
}

/// Translates one setting identity (refusal vocabulary) into
/// ProTUN's.
/// Translates one ProTUN setting identity back. The engine-only
/// [`EngineSettingType::CircumventionRouting`] has no protun
/// counterpart (protun's refusal vocabulary stops at six) and never
/// arrives from that direction.
pub fn setting_type_from_protun(setting: &LocalAgentSettingType) -> EngineSettingType {
    match setting {
        LocalAgentSettingType::NetshieldLevel => EngineSettingType::Netshield,
        LocalAgentSettingType::Bouncing => EngineSettingType::Bouncing,
        LocalAgentSettingType::PortForwarding => EngineSettingType::PortForwarding,
        LocalAgentSettingType::SplitTcp => EngineSettingType::SplitTcp,
        LocalAgentSettingType::SafeMode => EngineSettingType::SafeMode,
        LocalAgentSettingType::RandomNat => EngineSettingType::RandomNat,
    }
}

/// Translates the engine Muon environment into ProTUN's.
pub fn muon_env_to_protun(env: EngineMuonEnv) -> MuonEnv {
    match env {
        EngineMuonEnv::Prod => MuonEnv::Prod,
        EngineMuonEnv::Atlas { scientist } => MuonEnv::Atlas { scientist },
        EngineMuonEnv::CustomServers { servers } => MuonEnv::CustomServers { servers },
    }
}

/// Translates one ProTUN transport into the engine mirror.
pub fn transport_from_protun(protocol: Protocol) -> EngineTransport {
    match protocol {
        Protocol::WireguardUdp => EngineTransport::WireGuardUdp,
        Protocol::WireguardTcp => EngineTransport::WireGuardTcp,
        Protocol::Stealth => EngineTransport::Stealth,
    }
}

/// Translates one ProTUN peer reference into the engine mirror.
pub fn peer_from_protun(peer: &PeerConnectionInfo) -> EnginePeerRef {
    EnginePeerRef {
        peer_id: peer.peer_id.clone(),
        entry_ip: ip_from_protun(peer.entry_ip),
        protocol: transport_from_protun(peer.protocol),
        port: peer.port,
    }
}

/// Unwraps ProTUN's `IpAddress` newtype into std's (Copy).
pub fn ip_from_protun(address: protun::api::connection::IpAddress) -> IpAddr {
    address.0
}

/// Translates ProTUN's agent report into the engine mirror.
pub fn agent_info_from_protun(info: &AgentConnectionInfo) -> EngineAgentInfo {
    EngineAgentInfo {
        server_exit_v4: info.server_exit_v4.map(ip_from_protun),
        server_exit_v6: info.server_exit_v6.map(ip_from_protun),
        server_mtu: info.server_mtu,
        groups: info.groups.clone(),
        restrictions: info
            .restrictions
            .iter()
            .map(|restriction| match restriction {
                protun::api::local_agent::Restriction::Streaming { reason } => {
                    EngineRestriction::Streaming {
                        reason: reason.clone(),
                    }
                }
                protun::api::local_agent::Restriction::Torrent { reason } => {
                    EngineRestriction::Torrent {
                        reason: reason.clone(),
                    }
                }
                protun::api::local_agent::Restriction::Other { name, reason } => {
                    EngineRestriction::Other {
                        name: name.clone(),
                        reason: reason.clone(),
                    }
                }
            })
            .collect(),
        applied: settings_from_protun(info.settings.clone()),
    }
}

/// Translates a full ProTUN VPN state into the engine mirror (pure;
/// hermetically pinned per shape).
pub fn translate_state(state: &VpnState) -> EngineVpnState {
    let (interface_up, interface_error) = match &state.interface_state {
        InterfaceState::Up { error } => (true, error.as_ref().map(error_string)),
        InterfaceState::Down { last_error } => (false, last_error.as_ref().map(error_string)),
    };
    EngineVpnState {
        interface_up,
        interface_error,
        connection: match &state.connection_state {
            ConnectionState::Disconnected { error } => EngineConnectionState::Disconnected {
                error: error.as_ref().map(disconnect_reason_string),
            },
            ConnectionState::Connecting {
                peers,
                wait_reasons,
            } => EngineConnectionState::Connecting {
                peer_ids: peers.iter().map(|p| p.peer_id.clone()).collect(),
                waiting_for_network: wait_reasons.iter().any(|r| {
                    matches!(
                        r,
                        protun::api::state::PeerConnectionWaitReason::WaitingForNetwork
                    )
                }),
            },
            ConnectionState::ConnectingToLocalAgent { peer, wait_reason } => {
                EngineConnectionState::ConnectingToAgent {
                    peer_id: peer.peer_id.clone(),
                    wait: wait_reason.as_ref().map(|reason| match reason {
                        protun::api::state::AgentConnectionWaitReason::SoftJailed => {
                            EngineAgentWait::SoftJailed
                        }
                        protun::api::state::AgentConnectionWaitReason::HardJailed { jails } => {
                            EngineAgentWait::HardJailed {
                                jails: jails
                                    .iter()
                                    .map(|jail| EngineAgentJail {
                                        reason: match jail.reason {
                                            protun::api::local_agent::WaitJailReason::BadUserBehavior => EngineJailReason::BadUserBehavior,
                                            protun::api::local_agent::WaitJailReason::DisabledUser => EngineJailReason::DisabledUser,
                                            protun::api::local_agent::WaitJailReason::LowPlan => EngineJailReason::LowPlan,
                                            protun::api::local_agent::WaitJailReason::Need2FA => EngineJailReason::Need2FA,
                                            protun::api::local_agent::WaitJailReason::PendingInvoice => EngineJailReason::PendingInvoice,
                                            protun::api::local_agent::WaitJailReason::SessionOverLimit => EngineJailReason::SessionOverLimit,
                                            protun::api::local_agent::WaitJailReason::WaitingClientChallengeReply => EngineJailReason::WaitingClientChallengeReply,
                                            protun::api::local_agent::WaitJailReason::Internal => EngineJailReason::Internal,
                                            protun::api::local_agent::WaitJailReason::Other => EngineJailReason::Other,
                                        },
                                        code: jail.code,
                                        message: jail.message.clone(),
                                    })
                                    .collect(),
                            }
                        }
                    }),
                }
            }
            ConnectionState::Connected { peer, agent_info } => EngineConnectionState::Connected {
                peer: peer_from_protun(peer),
                agent: agent_info.as_ref().map(agent_info_from_protun),
            },
        },
    }
}

fn error_string(error: &protun::api::state::InterfaceError) -> String {
    match error {
        protun::api::state::InterfaceError::IoError { error } => error.clone(),
    }
}

fn disconnect_reason_string(reason: &protun::api::state::DisconnectReason) -> String {
    match reason {
        protun::api::state::DisconnectReason::TunEstablishError { message } => message.clone(),
    }
}

/// Translates one ProTUN event into zero or more engine events
/// (pure; the unknown-to-us shapes translate to nothing rather than
/// blocking the lane).
pub fn translate_event(event: &Event) -> Vec<EngineEvent> {
    match event {
        Event::ConnectionStats {
            received_bytes,
            sent_bytes,
            time_since_last_handshake,
            estimated_loss,
            estimated_round_trip_time,
            ..
        } => vec![EngineEvent::Stats(EngineStats {
            received_bytes: *received_bytes,
            sent_bytes: *sent_bytes,
            time_since_last_handshake: *time_since_last_handshake,
            estimated_loss: *estimated_loss,
            estimated_round_trip_time: *estimated_round_trip_time,
        })],
        Event::LocalAgentStats {
            bytes_received,
            bytes_sent,
            malicious_blocked,
            ads_blocked,
            trackers_blocked,
            adult_content_blocked,
            data_saved,
        } => vec![EngineEvent::AgentStats(EngineAgentStats {
            bytes_received: *bytes_received,
            bytes_sent: *bytes_sent,
            malicious_blocked: *malicious_blocked,
            ads_blocked: *ads_blocked,
            trackers_blocked: *trackers_blocked,
            adult_content_blocked: *adult_content_blocked,
            data_saved: *data_saved,
        })],
        Event::Error { error } => match error {
            ErrorEvent::ForkSelectorNeeded => vec![EngineEvent::ForkSelectorNeeded],
            ErrorEvent::CertificateRefreshFatalError => vec![EngineEvent::CertificateFatal],
            ErrorEvent::LocalAgentSettingPolicyRefused { setting } => {
                vec![EngineEvent::SettingRefused(setting_type_from_protun(
                    setting,
                ))]
            }
            ErrorEvent::ApiError {
                endpoint,
                http_code,
                refresh_token_invalid,
                ..
            } => vec![EngineEvent::ApiError {
                endpoint: match endpoint {
                    protun::api::events::ApiEndpoint::Auth => EngineApiEndpoint::Auth,
                    protun::api::events::ApiEndpoint::CertificateRefresh => {
                        EngineApiEndpoint::CertificateRefresh
                    }
                },
                http_code: *http_code,
                refresh_token_invalid: *refresh_token_invalid,
            }],
        },
        Event::PacketCaptureStarted { .. } | Event::PacketCaptureStopped { .. } => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// Why a connect refused.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The TUN device could not be created/attached.
    #[error("tun: {0}")]
    Tun(#[from] TunError),
    /// The candidate set could not be translated.
    #[error("translation: {0}")]
    Translation(#[from] ProtocolError),
}

/// The production mode composition (pure; FR-32A): `Some(LocalAgent
/// …)` for the production engine, `None` for the agent-less test
/// engine (whose mode `translate` already composed with the explicit
/// key).
fn local_agent_mode(mode: &EngineMode) -> Option<ConnectionMode> {
    match mode {
        EngineMode::LocalAgent {
            user_agent,
            app_version,
            muon_env,
            settings,
        } => Some(ConnectionMode::LocalAgent {
            user_agent: user_agent.clone(),
            app_version: app_version.clone(),
            settings: settings_to_protun(*settings),
            muon_env: muon_env_to_protun(muon_env.clone()),
        }),
        EngineMode::NoLocalAgent => None,
    }
}

/// The engine: stateless configuration plus the connect composition.
#[derive(Debug, Clone)]
pub struct ConnectionEngine {
    config: EngineConfig,
}

impl ConnectionEngine {
    /// An engine with `config`.
    pub fn new(config: EngineConfig) -> Self {
        Self { config }
    }

    /// The engine's configuration.
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Composes and starts one connection (FR-24/32A/32B/32D):
    /// translate the params, compose the mode, create + hand off the
    /// TUN descriptor, arm the mark callback, spawn ProTUN with
    /// non-blocking forwarding callbacks, and return the live handle.
    pub fn connect(
        &self,
        params: &TunnelParams,
        cache: Box<dyn PersistentCache>,
    ) -> Result<ActiveConnection, EngineError> {
        // The key policy follows the mode: production LocalAgent runs
        // keyless params (the cache holds the key, FR-32A); agent-less
        // tests must carry it (nothing else would provide one).
        let key_policy = match &self.config.mode {
            EngineMode::LocalAgent { .. } => KeyPolicy::FromCache,
            EngineMode::NoLocalAgent => KeyPolicy::Required,
        };
        let mut initial = translate_with_policy(params, key_policy)?;
        // Compose the mode: production overrides translate's interim
        // agent-less mode with the LocalAgent session (FR-32A); the
        // agent-less test mode KEEPS translate's composition — the
        // decoded client key lives there and ConnectionMode is not
        // Clone, so the override must be conditional, not a rebuild.
        if let Some(mode) = local_agent_mode(&self.config.mode) {
            initial.connection_mode = mode;
        }
        let tun = TunHandle::create(&self.config.if_name)?;
        let fd = tun.into_raw_fd();

        let mark_health = Arc::new(MarkHealth::new());
        let mark_callback = MarkingFdCallback::new(
            Arc::new(SoMarkApplier::new(self.config.bypass_mark)),
            mark_health.clone(),
        );

        // Bounded with a drop policy (the SEC gate's P2): protun's
        // thread NEVER blocks (FR-32D is absolute) and the queue can
        // never grow without bound — stats-class events drop under
        // pressure (their counters are pollable), a dropped STATE is
        // counted and observable so a wedged consumer reads as an
        // alarm, not a silent leak.
        let (event_tx, event_rx) = std::sync::mpsc::sync_channel(EVENT_CHANNEL_BOUND);
        let drops = Arc::new(EventDrops::default());
        let latest = Arc::new(Mutex::new(None));
        let reconciliation = Arc::new(Mutex::new(match &self.config.mode {
            EngineMode::LocalAgent { settings, .. } => FeatureReconciliation::new(*settings),
            EngineMode::NoLocalAgent => FeatureReconciliation::new(EngineAgentSettings::default()),
        }));
        let recovery = Arc::new(RecoverySlots::default());
        let callbacks = EngineCallbacks {
            event_tx,
            drops: drops.clone(),
            recovery: recovery.clone(),
            latest: latest.clone(),
            reconciliation: reconciliation.clone(),
        };

        // protun-internal hazards noted for the record (PR-3's
        // tracked item): unix_connect EXPECTS its mio poll/waker pair
        // (a panic there stranding the already-transferred fd is
        // protun's leak), and a factory error (corrupt cached
        // certificate/key) exits its thread AFTER connect() already
        // returned Ok — the observable is the event channel closing
        // (events() erroring Disconnected): the daemon treats that as
        // a fatal connection death.
        let connection = Connection::unix_connect(
            initial,
            Some(fd),
            Box::new(callbacks.clone()),
            Box::new(callbacks),
            Some(Box::new(mark_callback)),
            cache,
        );

        Ok(ActiveConnection {
            connection,
            if_name: self.config.if_name.clone(),
            mark_health,
            events: event_rx,
            drops,
            recovery: recovery.clone(),
            latest,
            reconciliation,
            requested: Mutex::new(match &self.config.mode {
                EngineMode::LocalAgent { settings, .. } => *settings,
                EngineMode::NoLocalAgent => EngineAgentSettings::default(),
            }),
            key_policy,
            mode: self.config.mode.clone(),
        })
    }
}

/// The forwarding lane's bound (events). States are change-gated
/// (low rate); stats are pull-limited; agent stats are the one
/// server-paced push — 1024 slots is minutes of adversarial spam,
/// dropped-and-counted rather than grown.
const EVENT_CHANNEL_BOUND: usize = 1024;

/// Observable drop accounting for the bounded forwarding lane.
#[derive(Debug, Default)]
struct EventDrops {
    stats: AtomicU64,
    states: AtomicU64,
}

impl EventDrops {
    fn note_stats_drop(&self) {
        self.stats.fetch_add(1, Ordering::Relaxed);
    }
    fn note_state_drop(&self) {
        self.states.fetch_add(1, Ordering::Relaxed);
    }
}

/// The forwarding callbacks (FR-32D): translate, record, try-send.
/// No blocking work ever runs on ProTUN's connection thread — under a
/// full queue the event DROPS (counted), it never waits. Mutexes
/// recover from poison (`into_inner`): no lock holder can panic, and
/// the getters already recover, so the callbacks match them.
#[derive(Clone)]
struct EngineCallbacks {
    event_tx: SyncSender<EngineEvent>,
    drops: Arc<EventDrops>,
    recovery: Arc<RecoverySlots>,
    latest: Arc<Mutex<Option<EngineVpnState>>>,
    reconciliation: Arc<Mutex<FeatureReconciliation>>,
}

impl EngineCallbacks {
    /// The never-blocking send with the drop policy.
    fn forward(&self, event: EngineEvent) {
        match self.event_tx.try_send(event) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(event)) => match &event {
                // Latest-wins with a RECOVERY SLOT (the bot round's
                // P2): FR-30's counters are pollable and a stale stat
                // is worthless — the NEWEST lands in the slot, so a
                // recovering consumer reads fresh numbers instead of
                // replaying stale queued samples (the drop policy was
                // oldest-wins in effect before).
                EngineEvent::Stats(stats) => {
                    if let Ok(mut slot) = self.recovery.latest_stats.lock() {
                        *slot = Some(LatestStats::WireGuard(*stats));
                    }
                    self.drops.note_stats_drop();
                }
                EngineEvent::AgentStats(stats) => {
                    if let Ok(mut slot) = self.recovery.latest_stats.lock() {
                        *slot = Some(LatestStats::Agent(*stats));
                    }
                    self.drops.note_stats_drop();
                }
                // A dropped STATE is a bug alarm: the poll surface
                // (`latest_state`) stays current even when the push
                // drops — the daemon reads `dropped_states() > 0` as
                // a wedged consumer.
                EngineEvent::State(_) => self.drops.note_state_drop(),
                // CONTROL events have no poll surface at all (the
                // bot round's P2): a CertificateFatal the consumer
                // never sees leaves a dead tunnel reporting live —
                // the NEWEST is retained in the recovery slot for
                // the consumer that drains after the full queue.
                critical => {
                    if let Ok(mut slot) = self.recovery.critical.lock() {
                        *slot = Some(critical.clone());
                    }
                    self.drops.note_state_drop();
                }
            },
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                // The handle is gone; nothing to forward to.
            }
        }
    }
}

impl protun::api::connection::StateChangedCallback for EngineCallbacks {
    fn on_state_changed(&self, state: VpnState) {
        let translated = translate_state(&state);
        // T-20's applied side: a Connected state's agent report is
        // the server's answer to the feature request.
        if let ConnectionState::Connected {
            agent_info: Some(info),
            ..
        } = &state.connection_state
        {
            let mut ledger = self
                .reconciliation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ledger.note_applied(settings_from_protun(info.settings.clone()));
        } else if let ConnectionState::ConnectingToLocalAgent { .. }
        | ConnectionState::Disconnected { .. } = &state.connection_state
        {
            // The bot round's P2: leaving Connected INVALIDATES the
            // applied snapshot — until the new agent session answers,
            // every requested setting reads UNCONFIRMED, never
            // confirmed-by-the-previous-server.
            let mut ledger = self
                .reconciliation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ledger.note_unconfirmed();
        }
        let mut slot = self
            .latest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = Some(translated.clone());
        drop(slot);
        self.forward(EngineEvent::State(translated));
    }
}

impl protun::api::connection::EventCallback for EngineCallbacks {
    fn on_event(&self, event: Event) {
        for translated in translate_event(&event) {
            // T-20's refusal side.
            if let EngineEvent::SettingRefused(setting) = &translated {
                let mut ledger = self
                    .reconciliation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                ledger.note_refused(*setting);
            }
            self.forward(translated);
        }
    }
}

/// The recovery slots for events the bounded queue could not
/// deliver (the bot round's P2s): a control event
/// (`CertificateFatal`/`ForkSelectorNeeded`/`SettingRefused`/`ApiError`)
/// has no `latest_state`-style poll surface, so the newest one is
/// RETAINED here for the consumer that drains after a full queue;
/// the newest STATISTICS land here too (the drop policy is
/// latest-wins, not oldest-wins).
#[derive(Debug, Default)]
pub struct RecoverySlots {
    critical: Mutex<Option<EngineEvent>>,
    latest_stats: Mutex<Option<LatestStats>>,
}

/// The newest statistics of either class (the recovery slot's
/// payload).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LatestStats {
    /// The newest WireGuard counters.
    WireGuard(EngineStats),
    /// The newest LocalAgent counters.
    Agent(EngineAgentStats),
}

/// A live connection (FR-28/32C: atomically updatable without tearing
/// down the frontend session).
pub struct ActiveConnection {
    connection: Connection,
    if_name: String,
    mark_health: Arc<MarkHealth>,
    events: Receiver<EngineEvent>,
    drops: Arc<EventDrops>,
    recovery: Arc<RecoverySlots>,
    latest: Arc<Mutex<Option<EngineVpnState>>>,
    reconciliation: Arc<Mutex<FeatureReconciliation>>,
    requested: Mutex<EngineAgentSettings>,
    key_policy: KeyPolicy,
    mode: EngineMode,
}

impl ActiveConnection {
    /// The engine event stream (states, stats, refusals, errors —
    /// FR-29/30's raw material, bounded with a counted drop
    /// policy). A `RecvError::Disconnected` means ProTUN's thread
    /// exited — including the factory-error death AFTER connect()
    /// returned Ok (corrupt cached certificate/key): the daemon
    /// treats it as a fatal connection death.
    pub fn events(&mut self) -> &mut Receiver<EngineEvent> {
        &mut self.events
    }

    /// The most recent state (a poll surface; the same value the last
    /// `State` event carried).
    pub fn latest_state(&self) -> Option<EngineVpnState> {
        self.latest.lock().ok().and_then(|slot| slot.clone())
    }

    /// The FR-32B health cell (M5's route-commit gate).
    pub fn mark_health(&self) -> &MarkHealth {
        &self.mark_health
    }

    /// A snapshot of the T-20 ledger (requested vs applied vs
    /// refused).
    pub fn reconciliation(&self) -> FeatureReconciliation {
        self.reconciliation
            .lock()
            .map(|ledger| ledger.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    /// Rotates the candidate peers on the live connection (FR-28's
    /// new endpoint, FR-32C's atomic update — the session survives).
    /// Rotates with the CONNECTION's key policy (the bot round's
    /// P1): a production LocalAgent connection runs keyless params
    /// (the cache holds the key), so the `Required` default
    /// `translate` would refuse every rotation with MissingKey.
    /// The TUN interface name this connection owns (cleanup claims,
    /// FR-31).
    pub fn interface_name(&self) -> &str {
        &self.if_name
    }

    pub fn update_peers(&self, params: &TunnelParams) -> Result<(), ProtocolError> {
        let translated = translate_with_policy(params, self.key_policy)?;
        self.connection.update_peers(translated.peers);
        Ok(())
    }
    /// Updates the LocalAgent feature request on the live connection
    /// (FR-32C). The T-20 ledger resets: the new request has no
    /// answer yet.
    pub fn update_agent_settings(&self, settings: EngineAgentSettings) {
        if let Ok(mut ledger) = self.reconciliation.lock() {
            ledger.note_requested(settings);
        }
        // The live request slot follows the update (the bot round's
        // P2): requested_settings() stays the honest view.
        if let Ok(mut requested) = self.requested.lock() {
            *requested = settings;
        }
        self.connection
            .update_local_agent_settings(settings_to_protun(settings));
    }

    /// Reports OS connectivity to ProTUN (network up/down/switch).
    pub fn on_connectivity_change(&self, event: ConnectivityChange) {
        let mapped = match event {
            ConnectivityChange::Up => ConnectivityEvent::Up,
            ConnectivityChange::Down => ConnectivityEvent::Down,
            ConnectivityChange::NetworkSwitch => ConnectivityEvent::NetworkSwitch,
        };
        self.connection.on_connectivity_change(mapped);
    }

    /// Asks ProTUN for a stats event (FR-30 pull).
    pub fn request_stats(&self) {
        self.connection.request_stats();
    }

    /// The engine mode this connection runs (agent vs agent-less).
    pub fn mode(&self) -> &EngineMode {
        &self.mode
    }

    /// Disconnects and waits for ProTUN's thread to stop. The TUN
    /// descriptor ProTUN owned closes with its stream — the interface
    /// dies with it (IT-1's ownership model). Consumes the handle:
    /// a disconnected connection is never reused (a moved value never
    /// reaches `Drop`, so the fire-and-forget below never
    /// double-sends).
    pub fn disconnect(self) {
        self.connection.disconnect_and_wait();
    }

    /// Swaps the TUN descriptor on the LIVE connection (FR-32C's
    /// `update_unix_tun` replacement seam — M5's route lanes may
    /// force a TUN swap without a session teardown). CONSUMES the
    /// handle (the bot round's P1): ProTUN's stream owns the new
    /// descriptor — a borrowed shape left two owners of one fd.
    pub fn update_tun(&self, handle: TunHandle) {
        self.connection.update_unix_tun(handle.into_stream_info());
    }
    pub fn dropped_stats(&self) -> u64 {
        self.drops.stats.load(Ordering::Relaxed)
    }

    /// How many STATE events the bounded lane dropped. Zero, always,
    /// in a healthy daemon: a nonzero count means the event consumer
    /// wedged while holding this handle alive — the poll surface
    /// (`latest_state`) stayed current, but the push lane did not.
    pub fn dropped_states(&self) -> u64 {
        self.drops.states.load(Ordering::Relaxed)
    }

    /// The RETAINED control event, if one was dropped by a full
    /// queue (the bot round's P2): takes it — a consumer that finds
    /// one must act on it (a `CertificateFatal` closes the
    /// connection; a fork selector must be provided) before
    /// draining further.
    pub fn take_critical_event(&self) -> Option<EngineEvent> {
        self.recovery
            .critical
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// The NEWEST statistics (the bot round's P2): the drop policy
    /// is latest-wins — a consumer recovering from a full queue
    /// reads the freshest counters here instead of replaying
    /// stale queued samples.
    pub fn latest_stats(&self) -> Option<LatestStats> {
        *self
            .recovery
            .latest_stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The LIVE requested feature set (the bot round's P2):
    /// `mode()` keeps the connect-time snapshot; this reflects
    /// `update_agent_settings` — the honest view for status.
    pub fn requested_settings(&self) -> EngineAgentSettings {
        *self
            .requested
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        // Never the waiting variant: Drop must not block a daemon
        // unwinding. Fire-and-forget disconnect stops ProTUN's run
        // loop, whose stream close tears the TUN down (the rust
        // gate's P1: an orphaned handle must not leave a live
        // tunnel). Only reached when `disconnect(self)` was NOT
        // called — the moved value never drops.
        self.connection.disconnect();
    }
}

/// OS connectivity changes, engine-mirrored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityChange {
    /// Network became available.
    Up,
    /// Network was lost.
    Down,
    /// The network switched (Wi-Fi to mobile, AP change, …).
    NetworkSwitch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use protun::api::connection::IpAddress;
    use protun::api::state::{DisconnectReason, InterfaceError, PeerConnectionWaitReason};

    fn peer_connection(peer_id: &str, protocol: Protocol, port: u16) -> PeerConnectionInfo {
        PeerConnectionInfo {
            peer_id: peer_id.to_owned(),
            entry_ip: IpAddress(IpAddr::V4(std::net::Ipv4Addr::new(185, 159, 158, 1))),
            protocol,
            port,
        }
    }

    /// The state translation is pinned shape-by-shape: every
    /// ProTUN state the pinned build can emit maps to the engine
    /// mirror with no data dropped on the floor that the daemon
    /// lane needs.
    #[test]
    fn translate_state_disconnected_with_error() {
        let state = VpnState {
            interface_state: InterfaceState::Down {
                last_error: Some(InterfaceError::IoError {
                    error: "tun vanished".to_owned(),
                }),
            },
            connection_state: ConnectionState::Disconnected {
                error: Some(DisconnectReason::TunEstablishError {
                    message: "attach refused".to_owned(),
                }),
            },
        };
        let translated = translate_state(&state);
        assert!(!translated.interface_up);
        assert_eq!(translated.interface_error.as_deref(), Some("tun vanished"));
        assert!(matches!(
            translated.connection,
            EngineConnectionState::Disconnected { ref error }
                if error.as_deref() == Some("attach refused")
        ));
    }

    #[test]
    fn translate_state_connecting_with_wait_reasons() {
        let state = VpnState {
            interface_state: InterfaceState::Up { error: None },
            connection_state: ConnectionState::Connecting {
                peers: vec![
                    peer_connection("uk-42", Protocol::WireguardUdp, 51820),
                    peer_connection("se-7", Protocol::Stealth, 443),
                ],
                wait_reasons: vec![PeerConnectionWaitReason::WaitingForNetwork],
            },
        };
        let translated = translate_state(&state);
        assert!(translated.interface_up);
        assert!(translated.interface_error.is_none());
        match translated.connection {
            EngineConnectionState::Connecting {
                peer_ids,
                waiting_for_network,
            } => {
                assert_eq!(peer_ids, vec!["uk-42".to_owned(), "se-7".to_owned()]);
                assert!(waiting_for_network, "the wait reason survives the mirror");
            }
            other => panic!("expected Connecting, got {other:?}"),
        }
    }

    #[test]
    fn translate_state_connected_with_agent_info() {
        let state = VpnState {
            interface_state: InterfaceState::Up { error: None },
            connection_state: ConnectionState::Connected {
                peer: peer_connection("uk-42", Protocol::WireguardTcp, 443),
                agent_info: Some(AgentConnectionInfo {
                    server_exit_v4: Some(IpAddress(IpAddr::V4(std::net::Ipv4Addr::new(
                        185, 159, 158, 2,
                    )))),
                    server_exit_v6: None,
                    settings: LocalAgentSettings {
                        netshield_level: Some(NetshieldLevel::MalwareFilter),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            },
        };
        let translated = translate_state(&state);
        match translated.connection {
            EngineConnectionState::Connected { peer, agent } => {
                assert_eq!(peer.peer_id, "uk-42");
                assert_eq!(peer.protocol, EngineTransport::WireGuardTcp);
                assert_eq!(peer.port, 443);
                let agent = agent.expect("the agent report survives the mirror");
                assert_eq!(
                    agent.server_exit_v4,
                    Some(IpAddr::V4(std::net::Ipv4Addr::new(185, 159, 158, 2)))
                );
                // T-20's applied side: the DOWNGRADED netshield level
                // is carried, not the request.
                assert_eq!(
                    agent.applied.netshield_level,
                    Some(EngineNetshield::MalwareFilter)
                );
            }
            other => panic!("expected Connected, got {other:?}"),
        }
    }

    #[test]
    fn translate_event_refusal_and_fatal_shapes() {
        let refusal = Event::Error {
            error: ErrorEvent::LocalAgentSettingPolicyRefused {
                setting: LocalAgentSettingType::NetshieldLevel,
            },
        };
        assert_eq!(
            translate_event(&refusal),
            vec![EngineEvent::SettingRefused(EngineSettingType::Netshield)]
        );

        let fatal = Event::Error {
            error: ErrorEvent::CertificateRefreshFatalError,
        };
        assert_eq!(translate_event(&fatal), vec![EngineEvent::CertificateFatal]);

        let api_error = Event::Error {
            error: ErrorEvent::ApiError {
                endpoint: protun::api::events::ApiEndpoint::CertificateRefresh,
                http_code: Some(422),
                proton_code: None,
                message: None,
                refresh_token_invalid: false,
            },
        };
        assert_eq!(
            translate_event(&api_error),
            vec![EngineEvent::ApiError {
                endpoint: EngineApiEndpoint::CertificateRefresh,
                http_code: Some(422),
                refresh_token_invalid: false,
            }]
        );
    }

    #[test]
    fn settings_roundtrip_all_netshield_levels() {
        let levels = [
            EngineNetshield::None,
            EngineNetshield::MalwareFilter,
            EngineNetshield::AdsAndMalwareFilter,
            EngineNetshield::AdultAndAdsAndMalwareFilter,
        ];
        for level in levels {
            let settings = EngineAgentSettings {
                netshield_level: Some(level),
                split_tcp: Some(true),
                port_forwarding: Some(false),
                random_nat: Some(true),
                soft_jail: None,
                circumvention_routing: None,
            };
            assert_eq!(
                settings_from_protun(settings_to_protun(settings)),
                settings,
                "netshield {level:?} survives the protun roundtrip"
            );
        }
    }

    #[test]
    fn compose_mode_localagent_carries_the_request() {
        let mode = EngineMode::LocalAgent {
            user_agent: "ProtonWire/0.1".to_owned(),
            app_version: "0.1.0".to_owned(),
            muon_env: EngineMuonEnv::Prod,
            settings: EngineAgentSettings {
                netshield_level: Some(EngineNetshield::AdsAndMalwareFilter),
                ..Default::default()
            },
        };
        match local_agent_mode(&mode).expect("production composes LocalAgent") {
            ConnectionMode::LocalAgent {
                user_agent,
                app_version,
                settings,
                muon_env,
            } => {
                assert_eq!(user_agent, "ProtonWire/0.1");
                assert_eq!(app_version, "0.1.0");
                assert!(
                    matches!(muon_env, MuonEnv::Prod),
                    "the env survives the map"
                );
                assert_eq!(
                    settings.netshield_level,
                    Some(NetshieldLevel::AdsAndMalwareFilter)
                );
            }
            other => panic!("expected LocalAgent mode, got {other:?}"),
        }
        // The agent-less test engine keeps translate's composition.
        assert!(local_agent_mode(&EngineMode::NoLocalAgent).is_none());
    }

    /// FR-7M: the agent wait/jail reason surfaces through the mirror
    /// — hard-jail codes and messages ride ConnectingToAgent.
    #[test]
    fn translate_state_connecting_to_agent_carries_the_jail() {
        let state = VpnState {
            interface_state: InterfaceState::Up { error: None },
            connection_state: ConnectionState::ConnectingToLocalAgent {
                peer: peer_connection("uk-42", Protocol::WireguardUdp, 51820),
                wait_reason: Some(protun::api::state::AgentConnectionWaitReason::HardJailed {
                    jails: vec![protun::api::local_agent::WaitJail {
                        reason: protun::api::local_agent::WaitJailReason::PendingInvoice,
                        code: 5001,
                        message: "pay your invoice".to_owned(),
                    }],
                }),
            },
        };
        let translated = translate_state(&state);
        match translated.connection {
            EngineConnectionState::ConnectingToAgent { peer_id, wait } => {
                assert_eq!(peer_id, "uk-42");
                match wait {
                    Some(EngineAgentWait::HardJailed { jails }) => {
                        assert_eq!(jails.len(), 1);
                        assert_eq!(jails[0].reason, EngineJailReason::PendingInvoice);
                        assert_eq!(jails[0].code, 5001);
                        assert_eq!(jails[0].message, "pay your invoice");
                    }
                    other => panic!("expected a hard jail, got {other:?}"),
                }
            }
            other => panic!("expected ConnectingToAgent, got {other:?}"),
        }
    }

    /// The bounded lane's drop policy (the SEC gate's P2): a full
    /// queue never blocks the callback — stats drop (counted) and
    /// states drop (counted, the alarm counter).
    #[test]
    fn full_queue_drops_stats_and_states_without_blocking() {
        let (event_tx, _event_rx) = std::sync::mpsc::sync_channel(1);
        let callbacks = EngineCallbacks {
            event_tx,
            drops: Arc::new(EventDrops::default()),
            recovery: Arc::new(RecoverySlots::default()),
            latest: Arc::new(Mutex::new(None)),
            reconciliation: Arc::new(Mutex::new(FeatureReconciliation::new(
                EngineAgentSettings::default(),
            ))),
        };
        let stats = || Event::ConnectionStats {
            timestamp_ms: 0,
            received_bytes: 1,
            sent_bytes: 2,
            time_since_last_handshake: Duration::ZERO,
            estimated_loss: 0.0,
            estimated_round_trip_time: Duration::ZERO,
        };
        // Fill the single slot, then push past it.
        use protun::api::connection::EventCallback as _;
        callbacks.on_event(stats());
        callbacks.on_event(stats());
        assert_eq!(callbacks.drops.stats.load(Ordering::Relaxed), 1);

        let state = VpnState {
            interface_state: InterfaceState::Up { error: None },
            connection_state: ConnectionState::Disconnected { error: None },
        };
        use protun::api::connection::StateChangedCallback as _;
        callbacks.on_state_changed(state);
        assert_eq!(
            callbacks.drops.states.load(Ordering::Relaxed),
            1,
            "a dropped state is the alarm counter, never silent"
        );
    }
}
