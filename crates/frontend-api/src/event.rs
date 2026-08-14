//! Daemon-pushed events with sequence numbers.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::VpnState;

/// Envelope for every daemon-pushed event. `seq` is monotonic per daemon
/// process lifetime; a client that observes a gap must resynchronize with a
/// [`crate::Request::GetState`] request (PRD FR-127D).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EventEnvelope {
    /// Monotonic sequence number.
    pub seq: u64,
    /// The event payload.
    pub event: Event,
}

/// Daemon events. Milestone 1 carries state transitions and notices; richer
/// events (feature reconciliation, catalog refresh results, conflict
/// detection) are additive variants in later milestones.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Event {
    /// The VPN state machine transitioned.
    StateChanged {
        /// Previous state.
        from: VpnState,
        /// New state.
        to: VpnState,
    },
    /// An informational or warning notice worth surfacing in clients.
    Notice {
        /// Severity of the notice.
        level: NoticeLevel,
        /// Already-redacted human-readable text.
        message: String,
    },
}

/// Severity for [`Event::Notice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum NoticeLevel {
    /// Informational.
    Info,
    /// Warning.
    Warning,
    /// Error.
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_envelope_wire_shape() {
        let envelope = EventEnvelope {
            seq: 42,
            event: Event::StateChanged {
                from: VpnState::Disconnected,
                to: VpnState::Connecting,
            },
        };
        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(json["seq"], 42);
        assert_eq!(json["event"]["kind"], "state-changed");
        assert_eq!(json["event"]["from"], "disconnected");
        assert_eq!(json["event"]["to"], "connecting");
    }
}
