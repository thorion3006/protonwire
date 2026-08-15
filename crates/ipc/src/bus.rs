//! In-daemon event fan-out to connected sessions.
//!
//! Sessions subscribe with a bounded queue. A session whose queue overflows
//! Sessions subscribe with a bounded queue. A session whose queue overflows
//! keeps its subscription: the overflow is dropped, and the next sequence
//! number after the queue drains lets the client detect the gap and
//! resynchronize with a `GetState` request — the documented recovery path
//! (PRD FR-127D). No event is ever blocking.
//! documented recovery path (PRD FR-127D). No event is ever blocking.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, mpsc};

use protonwire_frontend_api::ServerMessage;

/// Per-session outbound queue capacity. Small on purpose: a lagging client
/// must resync rather than buffer unboundedly. Shared with the session
/// writer channel so both bounds stay identical.
pub(crate) const SESSION_QUEUE_LEN: usize = 256;

/// Fan-out registry of live sessions.
#[derive(Debug, Default)]
pub struct EventBus {
    sessions: Mutex<HashMap<u64, mpsc::SyncSender<ServerMessage>>>,
    next_session: AtomicU64,
}

impl EventBus {
    /// An empty bus.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a session and returns its inbound queue.
    pub fn subscribe(&self) -> (u64, mpsc::Receiver<ServerMessage>) {
        let (tx, rx) = mpsc::sync_channel(SESSION_QUEUE_LEN);
        let id = self.next_session.fetch_add(1, Ordering::Relaxed);
        self.sessions.lock().expect("event bus lock").insert(id, tx);
        (id, rx)
    }

    /// Removes a session.
    pub fn unsubscribe(&self, id: u64) {
        self.sessions.lock().expect("event bus lock").remove(&id);
    }

    /// Pushes a message to every live session queue.
    ///
    /// A full queue retains the session (Codex PR review finding 1): the
    /// overflow is dropped, but the subscription survives so a later
    /// sequence number still reaches the lagging client once it drains —
    /// that later seq is what its gap detection needs to resynchronize
    /// (FR-127D). Only a disconnected receiver ends a subscription.
    pub fn publish(&self, message: ServerMessage) {
        let mut sessions = self.sessions.lock().expect("event bus lock");
        sessions.retain(|_, tx| {
            !matches!(
                tx.try_send(message.clone()),
                Err(mpsc::TrySendError::Disconnected(_))
            )
        });
    }

    /// Number of live sessions (diagnostics and tests).
    pub fn session_count(&self) -> usize {
        self.sessions.lock().expect("event bus lock").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protonwire_frontend_api::{Event, EventEnvelope};

    fn event_message(seq: u64) -> ServerMessage {
        ServerMessage::Event(EventEnvelope {
            seq,
            event: Event::Notice {
                level: protonwire_frontend_api::NoticeLevel::Info,
                message: "hello".into(),
            },
        })
    }

    #[test]
    fn publishes_to_all_subscribers() {
        let bus = EventBus::new();
        let (_, rx1) = bus.subscribe();
        let (_, rx2) = bus.subscribe();
        bus.publish(event_message(1));
        assert!(matches!(rx1.recv(), Ok(ServerMessage::Event(_))));
        assert!(matches!(rx2.recv(), Ok(ServerMessage::Event(_))));
        assert_eq!(bus.session_count(), 2);
    }

    #[test]
    fn unsubscribe_stops_delivery() {
        let bus = EventBus::new();
        let (id, rx) = bus.subscribe();
        bus.unsubscribe(id);
        bus.publish(event_message(1));
        assert!(rx.try_recv().is_err());
        assert_eq!(bus.session_count(), 0);
    }

    /// Codex PR review finding 1 (P1): a session whose queue overflows must
    /// STAY subscribed. Evicting it on `Full` leaves the client with no later
    /// sequence number, so `next_event` blocks forever instead of detecting
    /// the gap and resynchronizing (the documented recovery path, FR-127D).
    #[test]
    fn lagging_session_stays_subscribed_and_receives_later_events() {
        let bus = EventBus::new();
        let (id, rx) = bus.subscribe();
        let (_, rx2) = bus.subscribe();
        for seq in 0..(SESSION_QUEUE_LEN + 8) {
            bus.publish(event_message(seq as u64));
            // Keep the second session draining so it stays healthy.
            while rx2.try_recv().is_ok() {}
        }
        // The stuck session is still registered...
        assert_eq!(bus.session_count(), 2);
        // ...and its queue holds a bounded backlog ending below the newest
        // sequence (the overflow was dropped, not the subscription).
        let mut last_seen = None;
        while let Ok(ServerMessage::Event(envelope)) = rx.try_recv() {
            last_seen = Some(envelope.seq);
        }
        let backlog_end = last_seen.expect("backlog is non-empty");
        assert!(backlog_end < SESSION_QUEUE_LEN as u64 + 8);
        // Once the lagging session drains, the NEXT published event is
        // delivered — that later sequence number is exactly what the client
        // needs to detect the gap and resynchronize.
        bus.publish(event_message(9_999));
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(ServerMessage::Event(envelope)) => {
                assert!(envelope.seq > backlog_end, "gap must be observable");
            }
            other => panic!("lagging session must receive later events, got {other:?}"),
        }
        bus.unsubscribe(id);
        drop(rx2);
    }

    /// Only a DISCONNECTED receiver ends a subscription.
    #[test]
    fn disconnected_session_is_evicted() {
        let bus = EventBus::new();
        let (id, rx) = bus.subscribe();
        drop(rx);
        bus.publish(event_message(1));
        assert_eq!(bus.session_count(), 0);
        bus.unsubscribe(id);
    }
}
