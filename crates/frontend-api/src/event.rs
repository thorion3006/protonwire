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

/// Protocol version that introduced the reserved resync marker (X4,
/// round 8). The marker landed inside version 1 — before any client
/// shipped — so every in-tree client understands it and sessions
/// negotiated at 1 or above receive it. The constant exists so the
/// outbound fan-out filters by DECLARED introduction version instead of
/// an ad-hoc comparison; the next reserved outbound marker registers
/// its introduction version beside this one and reuses the same
/// reaches-version filter.
pub const RESYNC_MARKER_INTRODUCED_IN: u32 = 1;

/// Per-version outbound filter for the reserved resync marker: a
/// session negotiated below [`RESYNC_MARKER_INTRODUCED_IN`] must not
/// receive the reserved seq — such a peer recovers through the ordinary
/// sequence-gap resynchronization on the next real event instead of a
/// signal it cannot interpret. The daemon's session forwarder consults
/// this with the version negotiated at hello.
pub fn resync_marker_reaches(version: u32) -> bool {
    version >= RESYNC_MARKER_INTRODUCED_IN
}

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

/// Daemon events. Milestone 1 carries state transitions and notices;
/// Milestone 2 adds the catalog-refresh summary, the account-change
/// signal, and the scheduler notice (S2). Richer events remain additive
/// variants in later milestones.
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
    /// A server-catalog refresh finished; the result summary lets
    /// status surfaces report the last refresh outcome (FR-123) and
    /// tells clients when server data changed (FR-9).
    CatalogRefreshed {
        /// Outcome summary of the finished refresh.
        result: CatalogRefreshResult,
    },
    /// The authenticated account changed — login, logout, session
    /// refresh or import, or a stored-credential mutation. A bare
    /// signal: clients re-query account state (FR-7H) on receipt.
    AccountChanged,
    /// The single-flight metadata scheduler surfaced a condition worth
    /// displaying: the FR-11/FR-13I manual-refresh warning or an
    /// ER-16 suppression notice. Same level+message shape as
    /// [`Event::Notice`], attributable to the scheduler so clients can
    /// route it.
    SchedulerNotice {
        /// Severity of the notice.
        level: NoticeLevel,
        /// Already-redacted human-readable text.
        message: String,
    },
}

/// Outcome summary carried by [`Event::CatalogRefreshed`] (M2 S2):
/// mirrors the S0 catalog seam's `fetch(etag) → Changed | NotModified`
/// plus the stable refusal code on failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum CatalogRefreshResult {
    /// The refresh fetched and committed a new catalog revision.
    Changed,
    /// The upstream reported no change since the last fetch (an ETag
    /// match); the existing catalog stays authoritative.
    NotModified,
    /// The refresh was refused or failed; `code` is the stable
    /// machine-readable reason (for example a persisted ER-16
    /// suppression surfacing as [`crate::RpcErrorCode::RateLimited`]).
    Failed {
        /// Stable refusal code.
        code: crate::RpcErrorCode,
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

    /// X4 gating (M2 S2): the marker's introduction version is declared
    /// beside the marker and the outbound filter is exactly "reaches
    /// versions >= introduced-in". The forced pre-marker peer (version
    /// below the introduction) must not receive it; version 1 — the
    /// marker's introduction version and the oldest on the wire — does,
    /// as does everything newer.
    #[test]
    fn resync_marker_reaches_versions_at_its_introduction() {
        assert_eq!(
            RESYNC_MARKER_INTRODUCED_IN, 1,
            "the marker landed inside protocol version 1 (round 8, unshipped)"
        );
        assert!(
            !resync_marker_reaches(RESYNC_MARKER_INTRODUCED_IN - 1),
            "a pre-marker session must not receive the reserved seq"
        );
        assert!(resync_marker_reaches(RESYNC_MARKER_INTRODUCED_IN));
        assert!(resync_marker_reaches(crate::PROTOCOL_VERSION));
    }

    /// M2 S2 additive events: the wire shapes for the catalog-refresh
    /// summary, the account-changed signal, and the scheduler notice.
    #[test]
    fn m2_event_wire_shapes() {
        use crate::proto::RpcErrorCode;

        // The refresh summary: outcome-tagged, with the failure arm
        // carrying the stable refusal code.
        let refresh = EventEnvelope {
            seq: 10,
            event: Event::CatalogRefreshed {
                result: CatalogRefreshResult::NotModified,
            },
        };
        let json = serde_json::to_value(&refresh).unwrap();
        assert_eq!(json["seq"], 10);
        assert_eq!(json["event"]["kind"], "catalog-refreshed");
        assert_eq!(json["event"]["result"]["outcome"], "not-modified");
        let back: EventEnvelope = serde_json::from_value(json).unwrap();
        assert!(matches!(
            back.event,
            Event::CatalogRefreshed {
                result: CatalogRefreshResult::NotModified
            }
        ));
        let changed = serde_json::to_value(Event::CatalogRefreshed {
            result: CatalogRefreshResult::Changed,
        })
        .unwrap();
        assert_eq!(changed["result"]["outcome"], "changed");
        let failed = serde_json::to_value(Event::CatalogRefreshed {
            result: CatalogRefreshResult::Failed {
                code: RpcErrorCode::RateLimited,
            },
        })
        .unwrap();
        assert_eq!(failed["result"]["outcome"], "failed");
        assert_eq!(failed["result"]["code"], "rate-limited");

        // AccountChanged is a bare signal: no payload to version.
        let account = serde_json::to_value(Event::AccountChanged).unwrap();
        assert_eq!(account["kind"], "account-changed");
        assert_eq!(account.as_object().map(|o| o.len()), Some(1));

        // The scheduler notice mirrors Notice's level+message shape.
        let scheduler = serde_json::to_value(Event::SchedulerNotice {
            level: NoticeLevel::Warning,
            message: "refresh suppressed; next attempt after the deadline".into(),
        })
        .unwrap();
        assert_eq!(scheduler["kind"], "scheduler-notice");
        assert_eq!(scheduler["level"], "warning");
        assert_eq!(
            scheduler["message"],
            "refresh suppressed; next attempt after the deadline"
        );
    }
}
