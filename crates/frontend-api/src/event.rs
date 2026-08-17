//! Daemon-pushed events with sequence numbers.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::VpnState;

/// Sequence number reserved as the daemon's end-of-burst overflow signal.
///
/// A daemon's real `seq` starts at 1 and increments once per event, so no
/// process can ever legitimately reach 2^64 — the value is unreachable by
/// construction. When a session's bounded fan-out queue drops events
/// because the client is not keeping up (the retain-on-Full design) and the
/// burst ENDS there, no later sequence number ever arrives to make the gap
/// observable, and the lagging client would hold stale state indefinitely.
/// The daemon therefore emits an [`EventEnvelope`] whose `seq` is this
/// reserved value — carrying a real [`Event::Notice`] payload, so the frame
/// deserializes on every client — and a current SDK treats that envelope as
/// an immediate full-state resynchronization trigger
/// ([`crate::Request::GetState`], PRD FR-127D). The envelope is never
/// delivered as a normal event, and this value must never enter a client's
/// sequence cursor.
pub const EVENT_SEQ_RESYNC_NOW: u64 = u64::MAX;

/// Envelope for every daemon-pushed event. `seq` is monotonic per daemon
/// process lifetime; a client that observes a gap must resynchronize with a
/// [`crate::Request::GetState`] request (PRD FR-127D). The one value a real
/// event never carries is [`EVENT_SEQ_RESYNC_NOW`], reserved as the
/// end-of-burst overflow signal above.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EventEnvelope {
    /// Monotonic sequence number, never [`EVENT_SEQ_RESYNC_NOW`] for a
    /// genuine event.
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

    /// X4: the resync marker rides the EXISTING envelope wire shape — a
    /// reserved seq value, nothing structurally new — so every client can
    /// parse the frame. Pin both the reservation (the value is unreachable
    /// by any real per-process counter) and the round trip.
    #[test]
    fn resync_marker_seq_is_reserved_and_round_trips() {
        assert_eq!(EVENT_SEQ_RESYNC_NOW, u64::MAX);
        let marker = EventEnvelope {
            seq: EVENT_SEQ_RESYNC_NOW,
            event: Event::Notice {
                level: NoticeLevel::Warning,
                message: "event queue overflowed; resynchronize".into(),
            },
        };
        let json = serde_json::to_value(&marker).unwrap();
        assert_eq!(json["seq"], u64::MAX);
        let back: EventEnvelope = serde_json::from_value(json).unwrap();
        assert_eq!(back.seq, EVENT_SEQ_RESYNC_NOW);
    }
}
