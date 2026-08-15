//! Daemon state view models consumed by all clients.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// High-level VPN state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum VpnState {
    /// No tunnel exists.
    Disconnected,
    /// A connection attempt is in progress.
    Connecting,
    /// A tunnel is up.
    Connected,
    /// A teardown is in progress.
    Disconnecting,
}

impl std::fmt::Display for VpnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VpnState::Disconnected => "disconnected",
            VpnState::Connecting => "connecting",
            VpnState::Connected => "connected",
            VpnState::Disconnecting => "disconnecting",
        })
    }
}

/// Host network integration mode (PRD 6.6). ProtonWire always owns the tunnel
/// and privacy policy; the mode only controls uplink observation and DNS
/// cooperation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkIntegration {
    /// Pick NetworkManager or systemd-networkd when either owns the default
    /// uplink, otherwise native.
    Auto,
    /// Observe netlink directly.
    Native,
    /// Cooperate with NetworkManager.
    NetworkManager,
    /// Cooperate with systemd-networkd.
    Networkd,
}

impl NetworkIntegration {
    /// String form used in the `status` JSON document.
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkIntegration::Auto => "auto",
            NetworkIntegration::Native => "native",
            NetworkIntegration::NetworkManager => "network-manager",
            NetworkIntegration::Networkd => "networkd",
        }
    }
}

/// Full daemon state snapshot — the authoritative view clients resynchronize
/// against (PRD FR-127D). Connection details (server, tunnel statistics,
/// requested-vs-applied features) join this struct in Milestone 4+ as additive
/// optional fields with a protocol minor version bump.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DaemonState {
    /// Protocol version the daemon speaks.
    pub protocol_version: u32,
    /// Daemon build version.
    pub daemon_version: String,
    /// Current VPN state.
    pub vpn_state: VpnState,
    /// Configured network integration mode (the configured value in Milestone
    /// 1; the resolved adapter once Milestone 5 lands).
    pub network_integration: NetworkIntegration,
    /// UID of the user who owns the active or most recent connection attempt,
    /// if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_owner_uid: Option<u32>,
    /// Sequence number of the newest event already reflected in this
    /// snapshot. Daemons that predate the field omit it; clients treat
    /// `None` as "sequence unknown" and fall back to their gap event.
    ///
    /// The resynchronization race this closes (Codex PR review round 2,
    /// finding 1): `GetState` is a separate request, so events can be
    /// published while it is in flight and the snapshot can reflect
    /// sequences newer than the gap event that triggered the resync.
    /// Pairing the snapshot with its own sequence lets the SDK advance
    /// its cursor coherently instead of replaying older buffered events
    /// after the newer snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_event_seq: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::PROTOCOL_VERSION;

    #[test]
    fn state_serializes_prd_shapes() {
        let state = DaemonState {
            protocol_version: PROTOCOL_VERSION,
            daemon_version: "0.1.0".into(),
            vpn_state: VpnState::Disconnected,
            network_integration: NetworkIntegration::Auto,
            active_owner_uid: None,
            latest_event_seq: None,
        };
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["vpn_state"], "disconnected");
        assert_eq!(json["network_integration"], "auto");
        assert!(json.get("active_owner_uid").is_none());
        assert!(json.get("latest_event_seq").is_none());
    }

    /// Codex PR review round 2, finding 1: the field is additive-optional —
    /// a document from a daemon that never stamps it (or an older daemon)
    /// still deserializes, with the sequence reported as unknown.
    #[test]
    fn snapshot_sequence_is_optional_on_the_wire() {
        let stamped = serde_json::json!({
            "protocol_version": 1,
            "daemon_version": "0.1.0",
            "vpn_state": "disconnected",
            "network_integration": "auto",
            "latest_event_seq": 7,
        });
        let state: DaemonState = serde_json::from_value(stamped).unwrap();
        assert_eq!(state.latest_event_seq, Some(7));

        let legacy = serde_json::json!({
            "protocol_version": 1,
            "daemon_version": "0.1.0",
            "vpn_state": "disconnected",
            "network_integration": "auto",
        });
        let state: DaemonState = serde_json::from_value(legacy).unwrap();
        assert_eq!(state.latest_event_seq, None);
    }
}
