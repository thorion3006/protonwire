//! Daemon state machine and request dispatch.
//!
//! Milestone 1 scope: state snapshots, ping, sequencing of events, and typed
//! refusals for the connection lifecycle. The ProTUN-backed engine, selection
//! policies, and feature reconciliation attach here in later milestones
//! behind the adapter traits living in their own crates.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use protonwire_frontend_api::{
    DaemonState, Event, EventEnvelope, NetworkIntegration, NoticeLevel, PROTOCOL_VERSION, Request,
    RequestResult, RpcError, VpnState,
};
use protonwire_store::config::SystemConfig;

use crate::error::CoreError;

/// Where core publishes sequenced events. The daemon supplies an
/// implementation backed by the IPC event bus.
pub trait EventSink: Send + Sync {
    /// Publishes one already-sequenced event.
    fn publish(&self, event: EventEnvelope);
}

/// An [`EventSink`] built from a function.
pub struct EventSinkFn<F: Fn(EventEnvelope) + Send + Sync>(pub F);

impl<F: Fn(EventEnvelope) + Send + Sync> EventSink for EventSinkFn<F> {
    fn publish(&self, event: EventEnvelope) {
        (self.0)(event)
    }
}

/// The authoritative daemon state machine.
///
/// All mutation goes through methods on this type so every observer sees a
/// consistent, sequenced view.
pub struct DaemonCore {
    version: String,
    config: Arc<SystemConfig>,
    seq: AtomicU64,
    sink: Arc<dyn EventSink>,
    inner: std::sync::Mutex<CoreInner>,
}

struct CoreInner {
    vpn_state: VpnState,
    active_owner_uid: Option<u32>,
}

impl DaemonCore {
    /// Creates the core in the disconnected state.
    pub fn new(
        version: impl Into<String>,
        config: Arc<SystemConfig>,
        sink: Arc<dyn EventSink>,
    ) -> Self {
        Self {
            version: version.into(),
            config,
            seq: AtomicU64::new(0),
            sink,
            inner: std::sync::Mutex::new(CoreInner {
                vpn_state: VpnState::Disconnected,
                active_owner_uid: None,
            }),
        }
    }

    /// The daemon build version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The loaded and validated system configuration.
    pub fn config(&self) -> &Arc<SystemConfig> {
        &self.config
    }

    /// Sequence number of the newest event emitted so far.
    pub fn latest_event_seq(&self) -> u64 {
        self.seq.load(Ordering::SeqCst)
    }

    /// Full-state snapshot for `GetState`.
    pub fn state(&self) -> DaemonState {
        let inner = self.inner.lock().expect("core lock");
        // Stamped under the same lock emitters hold across mutation,
        // sequence allocation, and publication: the sequence reads back
        // exactly the set of events whose effects this snapshot reflects,
        // so a client can advance its resync cursor to it coherently
        // (Codex PR review round 2, finding 1).
        let latest_event_seq = self.seq.load(Ordering::SeqCst);
        DaemonState {
            protocol_version: PROTOCOL_VERSION,
            daemon_version: self.version.clone(),
            vpn_state: inner.vpn_state,
            network_integration: self.config.daemon.network_integration.into(),
            active_owner_uid: inner.active_owner_uid,
            latest_event_seq: Some(latest_event_seq),
        }
    }

    /// Executes one authenticated request (after IPC-level authorization).
    ///
    /// `_peer_uid` is the authenticated requesting UID; per-UID ownership
    /// enforcement keys off it once the Milestone 4 engine records real
    /// connection owners.
    pub fn handle_request(
        &self,
        _peer_uid: u32,
        request: Request,
    ) -> Result<RequestResult, RpcError> {
        match request {
            Request::Ping { nonce } => Ok(RequestResult::Pong { nonce }),
            Request::GetState => Ok(RequestResult::State {
                state: self.state(),
            }),
            Request::Connect { .. } => {
                // No state is committed on a failing path: an unprivileged
                // peer must not be able to claim the host-global owner slot
                // with a request that cannot succeed (security review
                // finding: owner squatting). Owner recording activates with
                // the Milestone 4 engine, which sets it only after the
                // transition to Connecting is confirmed; cross-UID refusal
                // then keys off that real owner.
                Err(CoreError::NotImplemented("tunnel connect lands in milestone 4").into_rpc())
            }
            Request::Disconnect => {
                Err(CoreError::NotImplemented("tunnel disconnect lands in milestone 4").into_rpc())
            }
            Request::Shutdown => {
                // Intercepted by the daemon (admin-gated) before reaching core.
                Err(CoreError::Internal("shutdown must be handled by the daemon".into()).into_rpc())
            }
        }
    }

    /// Transitions the VPN state, sequencing and publishing the event.
    ///
    /// Mutation, sequence allocation, and publication all happen under one
    /// hold of the state lock: concurrent emitters serialize there, so the
    /// order events reach the sink always matches their sequence numbers
    /// and `from`/`to` stay coherent (rust-review finding 2 — publishing
    /// after unlock allowed inversions that broke the monotonic-`seq`
    /// contract the client resync logic relies on).
    pub fn set_vpn_state(&self, to: VpnState) {
        let mut inner = self.inner.lock().expect("core lock");
        let from = inner.vpn_state;
        if from == to {
            return;
        }
        inner.vpn_state = to;
        self.emit_locked(Event::StateChanged { from, to }, &mut inner);
    }

    /// Publishes a notice.
    pub fn notice(&self, level: NoticeLevel, message: impl Into<String>) {
        let mut inner = self.inner.lock().expect("core lock");
        self.emit_locked(
            Event::Notice {
                level,
                message: message.into(),
            },
            &mut inner,
        );
    }

    /// The configured network integration mode as exposed in status.
    pub fn network_integration(&self) -> NetworkIntegration {
        self.config.daemon.network_integration.into()
    }

    /// Allocates the next sequence number and publishes. The `_proof`
    /// guard parameter makes the single-lock hold a compile-time property:
    /// every emitter holds `inner` across allocation and publication.
    fn emit_locked(&self, event: Event, _proof: &mut std::sync::MutexGuard<'_, CoreInner>) {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        self.sink.publish(EventEnvelope { seq, event });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn core() -> (DaemonCore, Arc<Mutex<Vec<EventEnvelope>>>) {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let sink = {
            let recorded = Arc::clone(&recorded);
            Arc::new(EventSinkFn(move |env| recorded.lock().unwrap().push(env)))
        };
        let config = Arc::new(SystemConfig::default());
        (DaemonCore::new("0.1.0-test", config, sink), recorded)
    }

    #[test]
    fn starts_disconnected_and_sequences_events() {
        let (core, recorded) = core();
        assert_eq!(core.state().vpn_state, VpnState::Disconnected);
        assert_eq!(core.latest_event_seq(), 0);

        core.set_vpn_state(VpnState::Connecting);
        core.set_vpn_state(VpnState::Connecting); // no-op, no event
        core.notice(NoticeLevel::Info, "hello");

        let events = recorded.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 1);
        assert!(matches!(events[0].event, Event::StateChanged { .. }));
        assert_eq!(events[1].seq, 2);
    }

    /// Codex PR review round 2, finding 1: the snapshot carries the sequence
    /// it reflects, so the SDK can pair `GetState` with its cursor instead
    /// of guessing from the gap event that triggered the resync.
    #[test]
    fn snapshot_stamps_the_sequence_it_reflects() {
        let (core, _) = core();
        assert_eq!(core.state().latest_event_seq, Some(0));
        core.notice(NoticeLevel::Info, "one");
        core.notice(NoticeLevel::Info, "two");
        assert_eq!(core.state().latest_event_seq, Some(2));
        core.set_vpn_state(VpnState::Connecting);
        assert_eq!(core.state().latest_event_seq, Some(3));
    }

    /// QA mutation gap (item G2): the snapshot stamp is read under the
    /// emitter lock, so a snapshot can never complete against a
    /// half-finished publication — it either predates the event entirely
    /// or reflects it (fields AND sequence) together. The EventSinkFn seam
    /// makes the interleaving deterministic: the emitter parks mid-publish
    /// while holding the state lock, and state() must queue behind it.
    ///
    /// Mutation-analysis note: a bare "read the atomic outside the lock"
    /// mutation is NOT distinguishable through this seam — because
    /// `emit_locked` allocates the sequence under the same lock that
    /// guards the fields, the field reads force state() to wait for the
    /// emitter regardless, and an unlocked read can only ever produce a
    /// stamp that LAGS the fields (never one that leads them), in a
    /// window no deterministic test can widen. What this test pins is the
    /// serialization the locked read is part of: no snapshot observes a
    /// sequence number whose event is still inside the sink.
    #[test]
    fn snapshot_stamp_waits_for_an_inflight_publication() {
        use std::sync::mpsc;

        let recorded = Arc::new(Mutex::new(Vec::new()));
        let (publish_started_tx, publish_started_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        // Channel endpoints are Send but not Sync; the sink closure must be
        // both, so each endpoint rides inside a Mutex.
        let publish_started_tx = Mutex::new(publish_started_tx);
        let release_rx = Mutex::new(release_rx);
        let sink = {
            let recorded = Arc::clone(&recorded);
            EventSinkFn(move |env| {
                recorded.lock().unwrap().push(env);
                // Signal, then park: the emitter holds the state lock here.
                let _ = publish_started_tx.lock().unwrap().send(());
                let _ = release_rx.lock().unwrap().recv();
            })
        };
        let core = Arc::new(DaemonCore::new(
            "0.1.0-test",
            Arc::new(SystemConfig::default()),
            Arc::new(sink),
        ));

        let emitter = {
            let core = Arc::clone(&core);
            std::thread::spawn(move || core.notice(NoticeLevel::Info, "in flight"))
        };
        assert!(
            publish_started_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok(),
            "emitter must reach the sink"
        );

        // Sequence 1 is allocated but NOT yet published (the sink is
        // parked). state() must block on the emitter's lock instead of
        // handing out a snapshot stamped Some(1).
        let snapshot = {
            let core = Arc::clone(&core);
            std::thread::spawn(move || core.state())
        };
        for _ in 0..8 {
            assert!(
                !snapshot.is_finished(),
                "state() observed the sequence of an unpublished event — \
                 the stamp is read outside the emitter lock"
            );
            std::thread::sleep(std::time::Duration::from_millis(15));
        }

        // Let the publication finish; now the stamp legitimately reads 1.
        release_tx.send(()).unwrap();
        let state = snapshot.join().unwrap();
        assert_eq!(state.latest_event_seq, Some(1));
        assert_eq!(recorded.lock().unwrap().len(), 1);
        emitter.join().unwrap();
    }

    /// Regression (rust-review finding 2): with several threads emitting
    /// concurrently, publication order must always match sequence order —
    /// an inversion makes clients see a fake gap and rewind their cursor.
    #[test]
    fn concurrent_emissions_publish_in_sequence_order() {
        let (core, recorded) = core();
        let core = Arc::new(core);
        let threads: Vec<_> = (0..4)
            .map(|t| {
                let core = Arc::clone(&core);
                std::thread::spawn(move || {
                    for i in 0..250 {
                        if (t + i) % 3 == 0 {
                            core.notice(NoticeLevel::Info, "tick");
                        } else {
                            core.set_vpn_state(VpnState::Connecting);
                            core.set_vpn_state(VpnState::Disconnecting);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let events = recorded.lock().unwrap();
        assert!(!events.is_empty());
        for pair in events.windows(2) {
            assert!(
                pair[0].seq < pair[1].seq,
                "publish order inverted: seq {} was published after seq {}",
                pair[1].seq,
                pair[0].seq
            );
        }
    }

    #[test]
    fn connect_refused_without_committing_owner_state() {
        let (core, _) = core();
        let err = core
            .handle_request(
                1000,
                Request::Connect {
                    target: protonwire_frontend_api::ConnectTarget::Fastest,
                },
            )
            .unwrap_err();
        assert_eq!(
            err.code,
            protonwire_frontend_api::RpcErrorCode::NotImplemented
        );
        // No owner was recorded: a failed request must not squat the
        // host-global owner slot (any subsequent user is equally free to
        // request, and status shows no owner).
        assert_eq!(core.state().active_owner_uid, None);
        let err = core
            .handle_request(
                2000,
                Request::Connect {
                    target: protonwire_frontend_api::ConnectTarget::Fastest,
                },
            )
            .unwrap_err();
        assert_eq!(
            err.code,
            protonwire_frontend_api::RpcErrorCode::NotImplemented
        );
    }

    #[test]
    fn ping_and_state_answer() {
        let (core, _) = core();
        match core
            .handle_request(0, Request::Ping { nonce: "x".into() })
            .unwrap()
        {
            RequestResult::Pong { nonce } => assert_eq!(nonce, "x"),
            other => panic!("unexpected: {other:?}"),
        }
        assert!(matches!(
            core.handle_request(0, Request::GetState).unwrap(),
            RequestResult::State { .. }
        ));
    }
}
