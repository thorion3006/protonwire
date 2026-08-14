//! In-daemon event fan-out to connected sessions.
//!
//! Sessions subscribe with a bounded queue. A session whose queue overflows
//! simply stops receiving events; the event sequence numbers let its client
//! detect the gap and resynchronize with a `GetState` request, which is the
//! documented recovery path (PRD FR-127D). No event is ever blocking.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, mpsc};

use protonwire_frontend_api::ServerMessage;

/// Per-session outbound queue capacity. Small on purpose: a lagging client
/// must resync rather than buffer unboundedly.
const SESSION_QUEUE_LEN: usize = 256;

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
    pub fn publish(&self, message: ServerMessage) {
        let mut sessions = self.sessions.lock().expect("event bus lock");
        sessions.retain(|_, tx| tx.try_send(message.clone()).is_ok());
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

    #[test]
    fn overflowing_session_is_dropped_not_blocked() {
        let bus = EventBus::new();
        let (id, rx) = bus.subscribe();
        let (_, rx2) = bus.subscribe();
        for seq in 0..(SESSION_QUEUE_LEN + 8) {
            bus.publish(event_message(seq as u64));
            // Keep the second session draining so it stays subscribed.
            while rx2.try_recv().is_ok() {}
        }
        // The stuck session was evicted...
        assert_eq!(bus.session_count(), 1);
        bus.unsubscribe(id);
        // ...while the healthy session kept receiving throughout, and the
        // stuck session's queue holds its bounded backlog.
        assert!(rx.try_recv().is_ok());
        drop(rx2);
    }
}
