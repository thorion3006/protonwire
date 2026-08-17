//! In-daemon event fan-out to connected sessions.
//!
//! Sessions subscribe with a bounded queue. A session whose queue overflows
//! keeps its subscription: the overflow is dropped, and the next sequence
//! number after the queue drains lets the client detect the gap and
//! resynchronize with a `GetState` request — the documented recovery path
//! (PRD FR-127D). No event is ever blocking.
//!
//! That later-seq recovery cannot help when the burst ENDS on the overflow
//! (X4, round 8): with nothing further published, no later seq ever
//! arrives, the gap stays invisible, and the lagging client holds stale
//! state indefinitely. A drop therefore also MARKS the session
//! (SessionEntry::overflowed); the session's forwarder observes the
//! mark once it resumes draining and sends the client the reserved
//! resync marker — see `server::handle_session`'s forwarder.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use protonwire_frontend_api::ServerMessage;

/// Per-session outbound queue capacity. Small on purpose: a lagging client
/// must resync rather than buffer unboundedly. Shared with the session
/// writer channel so both bounds stay identical.
pub(crate) const SESSION_QUEUE_LEN: usize = 256;

/// Maximum simultaneously served sessions; connections beyond this are
/// accepted and immediately closed to drain the backlog.
///
/// Enforced by an atomically reserved slot counter owned by the bus,
/// claimed BEFORE a connection's worker is spawned: a check against the
/// subscriber count races a concurrent accept burst, because the new
/// connection only registers once the spawned thread runs (Codex PR
/// review finding 2).
pub const MAX_SESSIONS: usize = 64;

/// One live session's fan-out registration.
#[derive(Debug)]
struct SessionEntry {
    /// The session's bounded inbound queue; the receiver is owned by the
    /// session's forwarder thread.
    tx: mpsc::SyncSender<ServerMessage>,
    /// Set whenever [`EventBus::publish`] dropped an event because this
    /// session's queue was full. Shared with the session's forwarder,
    /// which clears it (atomically, so exactly one marker is emitted per
    /// observed episode) and answers it with the reserved resync marker —
    /// the end-of-burst overflow signal of X4. Without the mark, a burst
    /// that ends on the drop would leave the client's gap undetectable:
    /// no later seq would ever arrive to reveal it.
    overflowed: Arc<AtomicBool>,
}

/// Fan-out registry of live sessions.
#[derive(Debug, Default)]
pub struct EventBus {
    sessions: Mutex<HashMap<u64, SessionEntry>>,
    next_session: AtomicU64,
    reserved: AtomicUsize,
}

impl EventBus {
    /// An empty bus.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a session and returns its inbound queue plus the overflow
    /// mark the forwarder watches (see SessionEntry::overflowed).
    pub fn subscribe(&self) -> (u64, mpsc::Receiver<ServerMessage>, Arc<AtomicBool>) {
        let (tx, rx) = mpsc::sync_channel(SESSION_QUEUE_LEN);
        let overflowed = Arc::new(AtomicBool::new(false));
        let id = self.next_session.fetch_add(1, Ordering::Relaxed);
        self.sessions.lock().expect("event bus lock").insert(
            id,
            SessionEntry {
                tx,
                overflowed: Arc::clone(&overflowed),
            },
        );
        (id, rx, overflowed)
    }

    /// Removes a session.
    pub fn unsubscribe(&self, id: u64) {
        self.sessions.lock().expect("event bus lock").remove(&id);
    }

    /// Atomically claims one of the [`MAX_SESSIONS`] session slots.
    ///
    /// Returns `false` (without claiming) when the server is at its
    /// ceiling. The caller MUST pair every `true` with
    /// [`EventBus::release_session`] on session end — `handle_session`'s
    /// drop guard does.
    pub fn try_reserve_session(&self) -> bool {
        match self.reserved.fetch_add(1, Ordering::SeqCst) {
            n if n < MAX_SESSIONS => true,
            _ => {
                self.reserved.fetch_sub(1, Ordering::SeqCst);
                false
            }
        }
    }

    /// Releases a slot claimed by [`EventBus::try_reserve_session`].
    pub fn release_session(&self) {
        self.reserved.fetch_sub(1, Ordering::SeqCst);
    }

    /// Number of currently reserved session slots (diagnostics and tests).
    pub fn active_sessions(&self) -> usize {
        self.reserved.load(Ordering::SeqCst)
    }

    /// Pushes a message to every live session queue.
    ///
    /// A full queue retains the session (Codex PR review finding 1): the
    /// overflow is dropped, but the subscription survives so a later
    /// sequence number still reaches the lagging client once it drains —
    /// that later seq is what its gap detection needs to resynchronize
    /// (FR-127D). The drop also sets the session's overflow mark (X4): a
    /// burst that ends right there would otherwise stay invisible, since
    /// no later seq is coming to reveal the gap; the forwarder answers the
    /// mark with the reserved resync marker. Only a disconnected receiver
    /// ends a subscription.
    pub fn publish(&self, message: ServerMessage) {
        let mut sessions = self.sessions.lock().expect("event bus lock");
        sessions.retain(|_, entry| {
            match entry.tx.try_send(message.clone()) {
                Ok(()) => true,
                Err(mpsc::TrySendError::Disconnected(_)) => false,
                // Retain AND mark: the subscription survives the drop, and
                // the forwarder must tell the client it happened (X4).
                Err(mpsc::TrySendError::Full(_)) => {
                    entry.overflowed.store(true, Ordering::SeqCst);
                    true
                }
            }
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
        let (_, rx1, _) = bus.subscribe();
        let (_, rx2, _) = bus.subscribe();
        bus.publish(event_message(1));
        assert!(matches!(rx1.recv(), Ok(ServerMessage::Event(_))));
        assert!(matches!(rx2.recv(), Ok(ServerMessage::Event(_))));
        assert_eq!(bus.session_count(), 2);
    }

    #[test]
    fn unsubscribe_stops_delivery() {
        let bus = EventBus::new();
        let (id, rx, _) = bus.subscribe();
        bus.unsubscribe(id);
        bus.publish(event_message(1));
        assert!(rx.try_recv().is_err());
        assert_eq!(bus.session_count(), 0);
    }

    /// X4 (round 8): an end-of-burst drop must be OBSERVABLE. Publishing
    /// past a full queue keeps the session subscribed (finding 1, pinned
    /// below) AND sets its overflow mark — the flag the session's
    /// forwarder converts into the reserved resync marker once it resumes
    /// draining. The mark stays set until the forwarder atomically claims
    /// it, and repeated drops in one episode collapse into the one mark.
    #[test]
    fn overflow_drops_mark_the_session_without_evicting_it() {
        let bus = EventBus::new();
        let (id, rx, overflowed) = bus.subscribe();
        for seq in 0..(SESSION_QUEUE_LEN + 8) {
            bus.publish(event_message(seq as u64));
        }
        assert_eq!(
            bus.session_count(),
            1,
            "a full queue must retain the subscription (finding 1)"
        );
        assert!(
            overflowed.load(Ordering::SeqCst),
            "the drop must mark the session so the forwarder can signal it (X4)"
        );
        // The mark survives the queue draining (the burst has ended; no
        // further publish will refresh it)...
        while rx.try_recv().is_ok() {}
        assert!(
            overflowed.load(Ordering::SeqCst),
            "the mark must persist until the forwarder claims it"
        );
        // ...and the forwarder's atomic claim sees it exactly once, so one
        // episode answers with one marker even after repeated drops.
        assert!(overflowed.swap(false, Ordering::SeqCst));
        assert!(!overflowed.swap(false, Ordering::SeqCst));
        bus.unsubscribe(id);
    }

    /// Codex PR review finding 1 (P1): a session whose queue overflows must
    /// STAY subscribed. Evicting it on `Full` leaves the client with no later
    /// sequence number, so `next_event` blocks forever instead of detecting
    /// the gap and resynchronizing (the documented recovery path, FR-127D).
    #[test]
    fn lagging_session_stays_subscribed_and_receives_later_events() {
        let bus = EventBus::new();
        let (id, rx, _) = bus.subscribe();
        let (_, rx2, _) = bus.subscribe();
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
        let (id, rx, _) = bus.subscribe();
        drop(rx);
        bus.publish(event_message(1));
        assert_eq!(bus.session_count(), 0);
        bus.unsubscribe(id);
    }

    /// Codex PR review finding 2: the slot counter enforces the ceiling
    /// atomically and only a successful claim counts.
    #[test]
    fn session_slots_are_reserved_up_to_the_ceiling_only() {
        let bus = EventBus::new();
        for _ in 0..MAX_SESSIONS {
            assert!(bus.try_reserve_session());
        }
        assert!(!bus.try_reserve_session());
        assert!(!bus.try_reserve_session());
        assert_eq!(bus.active_sessions(), MAX_SESSIONS);
        bus.release_session();
        assert!(bus.try_reserve_session());
        assert_eq!(bus.active_sessions(), MAX_SESSIONS);
    }
}
