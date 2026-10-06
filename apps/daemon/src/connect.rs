//! The daemon connection lane (M4 PR-5, FR-24/28/32A): the bridge
//! between the frontend's `Connect`/`Disconnect` and ProtonWire's
//! engine.
//!
//! One [`ConnectionLane`] per daemon owns the engine, the process-wide
//! persistent facade (each connection borrows it as a
//! [`SharedFacadeCache`] box ProTUN drops on disconnect), the event
//! pump thread (FR-32D's consumer), and the ACTIVE OWNER discipline:
//! one connection at a time, owned by the UID that requested it — a
//! second UID's connect refuses typed, never silently takes over
//! (FR-9's authorization floor).
//!
//! State events flow engine → [`map_vpn_state`] → the core state
//! machine's sequenced `set_vpn_state` (the process-wide event
//! sequence and the resync protocol stay intact).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use protonwire_core::state::DaemonCore as CoreState;
use protonwire_frontend_api::VpnState;
use protonwire_protocol::engine::{
    ActiveConnection, ConnectionEngine, EngineConfig, EngineConnectionState, EngineEvent,
    EngineMode, EngineMuonEnv, EngineVpnState,
};
use protonwire_protocol::params::TunnelParams;
use protonwire_protocol::{EngineError, PersistenceFacade, SharedFacadeCache};

/// The bypass mark (FR-32B): M5's policy routes match this value; the
/// table IDs (51820-51822) live beside it in `protonwire_net`.
pub const BYPASS_MARK: u32 = 0x51820;

/// Why a lane call refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LaneRefusal {
    /// Another UID owns the active connection.
    #[error("uid {owner} owns the active connection")]
    NotOwner {
        /// The owning UID.
        owner: u32,
    },
    /// Nothing is connected.
    #[error("no active connection")]
    NoActiveConnection,
    /// The daemon is shutting down; no new connections start.
    #[error("the daemon is draining")]
    Draining,
    /// A reconnect is in its serialized teardown window (the bot
    /// round-12 P2); retry.
    #[error("a reconnect is in progress; retry")]
    Reconnecting,
    /// A disconnect is mid-teardown (the bot round-24 P2); retry —
    /// the lane frees when the join completes.
    #[error("a disconnect is in progress; retry")]
    Disconnecting,
}

/// A failed connect: the typed refusal or the engine's own error.
#[derive(Debug, thiserror::Error)]
pub enum LaneError {
    /// The owner gate refused.
    #[error("{0}")]
    Refused(#[from] LaneRefusal),
    /// The engine could not compose/start the connection.
    #[error("{0}")]
    Engine(#[from] EngineError),
}

/// The owner gate (pure, pinned): one connection, one owner.
fn gate_owner(current: Option<u32>, requester: u32) -> Result<(), LaneRefusal> {
    match current {
        Some(owner) if owner != requester => Err(LaneRefusal::NotOwner { owner }),
        _ => Ok(()),
    }
}

/// Maps one engine state onto the frontend's VPN state machine
/// (pure, pinned shape-by-shape).
pub fn map_vpn_state(state: &EngineVpnState) -> VpnState {
    match state.connection {
        EngineConnectionState::Disconnected { .. } => VpnState::Disconnected,
        EngineConnectionState::Connecting { .. }
        | EngineConnectionState::ConnectingToAgent { .. } => VpnState::Connecting,
        EngineConnectionState::Connected { .. } => VpnState::Connected,
    }
}

/// The shared connection slot: the pump reads events from it, the
/// lane tears it down — one owner at a time via `take`.
type ConnectionSlot = Arc<Mutex<Option<ActiveConnection>>>;

struct ActiveLane {
    connection: ConnectionSlot,
    pump: JoinHandle<()>,
}

impl ActiveLane {
    /// Takes the connection out (whoever gets it first) and waits for
    /// the pump to exit — teardown and pump-death race for the same
    /// slot, exactly once either way.
    fn teardown(self) {
        let taken = self.connection.lock().map(|mut slot| slot.take());
        if let Ok(Some(connection)) = taken {
            connection.disconnect();
        }
        let _ = self.pump.join();
    }

    /// RETIRES the slot first (the bot round-33 P2), handing the
    /// connection back: the pump's retirement check sees an empty
    /// slot the moment the caller decides to tear down — a dequeued
    /// stale state can no longer observe the populated slot and
    /// publish through the transition. The caller then publishes the
    /// transition and calls finish_tear to disconnect and join.
    fn retire(self) -> (Option<ActiveConnection>, JoinHandle<()>) {
        let taken = self.connection.lock().map(|mut slot| slot.take());
        (taken.ok().flatten(), self.pump)
    }
}

/// The second half of [`ActiveLane::retire`]: disconnect the retired
/// connection and join the pump.
fn finish_tear(retired: Option<ActiveConnection>, pump: JoinHandle<()>) {
    if let Some(connection) = retired {
        connection.disconnect();
    }
    let _ = pump.join();
}

#[derive(Default)]
struct LaneState {
    active: Option<ActiveLane>,
    owner: Option<u32>,
    // A reconnect's guard-drop window (the bot round-12 P2): while
    // set, connect() refuses — an interloper cannot install a lane
    // the reconnecting owner would then clobber or leak.
    reconnecting: bool,
    /// An ordinary disconnect's teardown window (the bot round-23 P2):
    /// armed before the guard drop, cleared after the join — the lane
    /// never looks free mid-teardown.
    disconnecting: bool,
    /// A drain's teardown is IN PROGRESS (the bot round-38 P2): armed
    /// by the drain caller that took the active lane, cleared after
    /// its teardown joins — concurrent drain callers wait it out, so
    /// the blocking-shutdown contract holds for EVERY caller, not
    /// just the one that won the take.
    drain_in_progress: bool,
}

/// Whether drain's wait loop must yield right now: a user window
/// (reconnecting/disconnecting — the round-28 discipline) or ANOTHER
/// drain's in-progress teardown. Pure so the serialization contract
/// is testable without a live engine.
fn drain_waits(lane: &LaneState) -> bool {
    lane.drain_in_progress || lane.reconnecting || lane.disconnecting
}

/// The lane's shared state: the pump must retire the lane when the
// engine dies on its own (the bot round's P2) — an Arc'd lane the
// pump and the daemon-side methods share.
type SharedLane = Arc<Mutex<LaneState>>;

/// The disconnect ADMISSION decision: which window (if any) refuses
/// this disconnect before the owner gate. Pure so the window contract
/// is testable without a live engine (the round-38 gap was a missing
/// arm here). Administrator first: a draining daemon owns the lane
/// outright — the user windows only refuse when no drain is armed.
///
/// The windows it guards (each a landed round): RECONNECTING (the
/// round-20 P2 — an owner reconnect temporarily sets owner=None with
/// no active lane; a disconnect here would "succeed" on the empty
/// lane and the in-flight reconnect would then install a tunnel AFTER
/// the completed disconnect), DISCONNECTING (the round-24 P2 — the
/// first disconnect took the lane and is joining its pump; a second
/// would "succeed" on the empty lane and CLEAR the window's flag
/// while the first teardown still runs), and DRAINING (the round-38
/// P2 — drain takes the lane and tears it down with no transition
/// flag armed; between its take and the join the lane reads empty
/// and unowned, and a disconnect "succeeded" on it while the pump
/// and TUN teardown still ran).
fn disconnect_refusal(lane: &LaneState, draining: bool) -> Option<LaneRefusal> {
    if draining {
        return Some(LaneRefusal::Draining);
    }
    if lane.reconnecting {
        return Some(LaneRefusal::Reconnecting);
    }
    if lane.disconnecting {
        return Some(LaneRefusal::Disconnecting);
    }
    None
}

/// The lane. Construct once at daemon startup with the production
/// mode; the engine inside is stateless configuration.
pub struct ConnectionLane {
    engine: ConnectionEngine,
    facade: Arc<PersistenceFacade>,
    core: Arc<CoreState>,
    state: SharedLane,
    draining: AtomicBool,
}

impl ConnectionLane {
    /// The production lane: LocalAgent mode over the encrypted cache
    /// (FR-32A), interface name from the daemon config (FR-26).
    pub fn new(
        if_name: String,
        user_agent: String,
        app_version: String,
        facade: Arc<PersistenceFacade>,
        core: Arc<CoreState>,
    ) -> Self {
        Self {
            engine: ConnectionEngine::new(EngineConfig {
                if_name,
                bypass_mark: BYPASS_MARK,
                mode: EngineMode::LocalAgent {
                    user_agent,
                    app_version,
                    muon_env: EngineMuonEnv::Prod,
                    settings: Default::default(),
                },
            }),
            facade,
            core,
            state: Arc::new(Mutex::new(LaneState::default())),
            draining: AtomicBool::new(false),
        }
    }

    /// The UID owning the active connection, if any (the status
    /// surface's `active_owner_uid`).
    pub fn active_owner_uid(&self) -> Option<u32> {
        self.state.lock().ok().and_then(|lane| lane.owner)
    }

    /// Starts one connection for `uid` (the IPC-authenticated peer).
    /// The facade rides in as a shared box; the pump thread drains the
    /// engine's events into the core state machine until the
    /// connection dies.
    pub fn connect(&self, uid: u32, params: &TunnelParams) -> Result<(), LaneError> {
        let mut lane = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        gate_owner(lane.owner, uid)?;
        if self.draining.load(Ordering::SeqCst) {
            return Err(LaneRefusal::Draining.into());
        }
        // The SPECIFIC window's refusal (the bot round-26 P2): the
        // caller must be able to distinguish the two teardown
        // windows — retry timing and diagnostics differ.
        if lane.reconnecting {
            return Err(LaneRefusal::Reconnecting.into());
        }
        if lane.disconnecting {
            return Err(LaneRefusal::Disconnecting.into());
        }
        // Reconnect by the owner: tear the previous session down first
        // (FR-28's reconnect IS a fresh connection — peer rotation on
        // a LIVE session is update_peers, the engine's own surface).
        // NO JOIN UNDER THE LANE LOCK (the refactor pass's P1): the
        // pump's retire_lane needs this same mutex on engine death —
        // dropping the guard before joining breaks the circular wait.
        // The WINDOW is armed HERE (the bot round-14 P2: the round-13
        // flag was checked but never SET — the interloper exclusion
        // did not exist): reconnecting = true travels with the guard
        // drop and is only cleared after the engine attempt.
        lane.reconnecting = true;
        let superseded = lane.active.take();
        // The old owner is cleared BEFORE the engine attempt: a FAILED
        // reconnect must not leave a phantom owner locking every other
        // UID out with no tunnel existing (the gate's P2 — no state
        // commits on failing paths; the owner is recorded only after a
        // confirmed start).
        lane.owner = None;
        drop(lane);
        if let Some(active) = superseded {
            // The REPLACEMENT publishes its transition too (the bot
            // round-31 P2): teardown-observed publishing is silent
            // (round-28) and the old Connected would read as live
            // through the whole setup. RETIRE FIRST (the bot round-33
            // P2): the slot empties BEFORE the transition publishes —
            // a just-dequeued stale state meets an empty slot at the
            // retirement check and never reverts Disconnecting.
            let (retired, pump) = active.retire();
            self.core.set_vpn_state(VpnState::Disconnecting);
            finish_tear(retired, pump);
        }
        let mut lane = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Re-acquiring may observe a pump-retired lane — the same
        // empty, unowned state we want. The window closes BEFORE the
        // engine attempt (a failure below leaves the lane open, not
        // wedged). The DRAINING flag is RE-CHECKED here (the bot
        // round-13 P2): drain may have set it and observed the
        // temporarily empty slot while the lock was down — starting
        // an engine connection now would install a tunnel outside
        // the administrator's controlled teardown. The reconnecting
        // flag STAYS ARMED through the setup (the bot round-30 P2):
        // clearing it before engine.connect let the lane look
        // completely free mid-setup — a drain observed no active
        // lane and returned before the installation, a concurrent
        // connect superseded it. It clears only when the result is
        // atomically installed (or on the way out of a failure).
        if self.draining.load(Ordering::SeqCst) {
            lane.reconnecting = false;
            return Err(LaneRefusal::Draining.into());
        }
        lane.owner = None;
        drop(lane);
        let connection = match self.engine.connect(
            params,
            Box::new(SharedFacadeCache(Arc::clone(&self.facade))),
        ) {
            Ok(connection) => connection,
            Err(error) => {
                // The TERMINAL publish on the failure path (the bot
                // round-29 P2): the previous lane is already torn
                // down and the pump's None arm now intentionally
                // publishes nothing — without this, the core could
                // read Connected/Connecting forever with no active
                // slot or TUN.
                self.core.set_vpn_state(VpnState::Disconnected);
                self.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .reconnecting = false;
                return Err(error.into());
            }
        };
        let mut lane = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let slot: ConnectionSlot = Arc::new(Mutex::new(Some(connection)));
        let core = Arc::clone(&self.core);
        let pump_slot = Arc::clone(&slot);
        // A WEAK lane reference (the bot round-18 P2): a strong Arc
        // from the pump back into LaneState (which holds the
        // ActiveLane and the slot) formed an ownership CYCLE — a
        // ConnectionLane dropped without drain() (an early return or
        // unwind in the daemon composition) left nothing able to take
        // the connection, so ActiveConnection::drop never ran and the
        // ProTUN session/TUN outlived the lane. Weak breaks the cycle;
        // the pump's retirement upgrades only while the lane lives
        // (a dropped lane needs no retirement — its drop IS one).
        let pump_lane = Arc::downgrade(&self.state);
        let pump = std::thread::spawn(move || pump_events(&pump_slot, &pump_lane, &core));
        lane.active = Some(ActiveLane {
            connection: slot,
            pump,
        });
        lane.owner = Some(uid);
        // The window closes HERE (the bot round-30 P2): the result is
        // atomically installed — active lane, owner, and the flag
        // clear under one guard; the mid-setup free-lane window no
        // longer exists.
        lane.reconnecting = false;
        Ok(())
    }

    /// Tears the active connection down. Only the owner (a disconnect
    /// with no active connection is an idempotent success).
    pub fn disconnect(&self, uid: u32) -> Result<(), LaneRefusal> {
        let mut lane = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // The window refusals are ONE admission decision (pure, so
        // the contract is testable without a live engine). The
        // draining read rides THIS guard: drain arms the flag before
        // its take (round-28), so a disconnect acquiring the guard
        // after the take sees it — and one that won the guard first
        // is waited out by drain's loop, its teardown finishing
        // before its own Ok.
        if let Some(refusal) = disconnect_refusal(&lane, self.draining.load(Ordering::SeqCst)) {
            return Err(refusal);
        }
        gate_owner(lane.owner, uid)?;
        // NO JOIN UNDER THE LANE LOCK (the refactor pass's P1): take
        // the entry, clear the owner, DROP the guard, then join — the
        // pump's retire_lane parks on this mutex at engine death.
        // The DISCONNECTING window is armed first (the bot round-23
        // P2): the lane must not look free while the teardown runs —
        // a concurrent connect hit a spurious setup failure (the old
        // connection still owned the TUN), a concurrent drain
        // returned without joining the pump.
        lane.disconnecting = true;
        let active = lane.active.take();
        lane.owner = None;
        drop(lane);
        // RETIRE FIRST (the bot round-33 P2): the slot empties
        // BEFORE Disconnecting publishes — a just-dequeued stale
        // state meets the empty slot at the retirement check and
        // cannot revert the transition mid-join. The terminal lands
        // after the join (round-26); idempotent when nothing was
        // taken (round-27).
        if let Some(active) = active {
            let (retired, pump) = active.retire();
            self.core.set_vpn_state(VpnState::Disconnecting);
            finish_tear(retired, pump);
            self.core.set_vpn_state(VpnState::Disconnected);
        }
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .disconnecting = false;
        Ok(())
    }

    /// Daemon shutdown: unconditional teardown (the administrator's
    /// lane, not a user's — no owner gate), blocking until the pump
    /// exits so no event races the IPC socket's close.
    pub fn drain(&self) {
        self.draining.store(true, Ordering::SeqCst);
        // The flag check AND the take under ONE guard (the bot
        // round-28 P2): a separate take-acquisition let a disconnect
        // slip into the gap (set its flag, take the lane, start its
        // join) — drain then saw None and returned while the pump
        // still ran. The window check and active.take() are now one
        // critical section; the join still runs guard-free (the
        // round-21 no-join-under-lock discipline).
        //
        // Concurrent drain callers SERIALIZE (the bot round-38 P2):
        // the first caller's teardown arms no transition flag, so a
        // second shutdown path observed the taken lane as idle and
        // returned while the first pump/TUN teardown still ran. The
        // take-armed drain_in_progress (cleared below, after the
        // teardown joins) makes every later caller WAIT for the
        // teardown's completion — this method blocks for EVERY
        // caller, not just the one that won the take. The `draining`
        // atomic stays armed forever (shutdown is terminal; it only
        // refuses new work) and cannot carry this meaning.
        let mut armed = false;
        let active = loop {
            let mut lane = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if drain_waits(&lane) {
                drop(lane);
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            if lane.active.is_some() {
                lane.drain_in_progress = true;
                armed = true;
            }
            lane.owner = None;
            break lane.active.take();
        };
        if let Some(active) = active {
            active.teardown();
        }
        if armed {
            // Released only by the caller that armed it; a waiter
            // that looped past another drain's teardown breaks on
            // the empty lane with armed == false and clears nothing.
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .drain_in_progress = false;
        }
    }
}
/// The pump's wait cadence: every slot-guard hold is bounded by this
/// timeout, so teardown's `take()` never waits longer than one cadence
/// on a pump that is itself waiting on a silent peer (the rust gate's
/// P1: a blocking recv under the mutex deadlocked every teardown path
/// against protun's change-gated, pull-only event stream).
const PUMP_POLL: Duration = Duration::from_millis(200);

/// Pumps engine events into the core state machine until the channel
/// dies (teardown takes the connection — its Drop closes the engine —
/// or the engine died on its own; either way the terminal state is
/// published and the lane RETIRED, never left stranded at
/// Connecting/Connected with a dead owner). Runs on its own thread;
/// every step is non-blocking on the engine side.
/// The terminal teardown (the engine contract: the caller must close
/// the connection on a fatal certificate-refresh failure — delivered
fn terminate_on_fatal(
    slot: &ConnectionSlot,
    lane: &std::sync::Weak<Mutex<LaneState>>,
    core: &CoreState,
) -> bool {
    // CLAIM-OR-YIELD (the bot round-35 P2): take the connection to
    // establish this pump owns the fatal cleanup; a teardown that
    // retired the slot first owns the terminal publish — publishing
    // here would overwrite its Disconnecting with a false terminal
    // mid-join. Returns whether the caller should continue its own
    // teardown handling (the claimed arm disconnects, publishes the
    // terminal, retires the lane).
    let Some(connection) = slot.lock().ok().and_then(|mut guard| guard.take()) else {
        tracing::warn!(
            "certificate refresh failed terminally — teardown already owns the slot; \
             the caller publishes the terminal state"
        );
        return true;
    };
    tracing::warn!("certificate refresh failed terminally — tearing the session down");
    connection.disconnect();
    core.set_vpn_state(VpnState::Disconnected);
    retire_lane(slot, lane);
    true
}

fn pump_events(slot: &ConnectionSlot, lane: &std::sync::Weak<Mutex<LaneState>>, core: &CoreState) {
    let mut last: Option<VpnState> = None;
    let mut dropped_watermark: u64 = 0;
    let mut backlog: bool = false;
    loop {
        let received = slot.lock().ok().and_then(|mut guard| {
            guard
                .as_mut()
                .map(|connection| connection.events().recv_timeout(PUMP_POLL))
        });
        let event = match received {
            Some(Ok(event)) => {
                // RECONCILE BEFORE PROCESSING (the bot round-29 P2):
                // if the queue dropped a state, THIS dequeued item is
                // pre-drop — arming the backlog and publishing the
                // authoritative snapshot FIRST means the stale
                // transition is suppressed here (its sequence was
                // never spent on a misleading state).
                if reconcile_drops(slot, core, &mut last, &mut dropped_watermark, &mut backlog) {
                    terminate_on_fatal(slot, lane, core);
                    break;
                }
                // A received event does NOT disarm the backlog (the
                // bot round-16 P2): the queue may still hold PRE-DROP
                // states behind this one. The backlog stays armed until
                // the queue is QUIET (the timeout arm's reconcile runs
                // with an empty queue behind it); every quiet cadence
                // re-reconciles in the meantime.
                event
            }
            Some(Err(std::sync::mpsc::RecvTimeoutError::Timeout)) => {
                // LANE-DROPPED CHECK (the bot round-21 P2): the only
                // upgrade site was retire_lane AFTER a terminal — the
                // healthy-lane case looped forever holding the slot
                // (the session and TUN leaked). The quiet cadence
                // checks: a lane that can no longer upgrade has been
                // dropped — exit, taking the slot (and the
                // ActiveConnection) with us.
                if lane.upgrade().is_none() {
                    if let Some(connection) = slot.lock().ok().and_then(|mut guard| guard.take()) {
                        connection.disconnect();
                    }
                    break;
                }
                // The quiet path still converges (the bot round's
                // P2): a consumer that stalled while the bounded
                // engine queue dropped states is caught up NOW —
                // reconcile the core with the engine's authoritative
                // poll surface instead of leaving the frontend state
                // stale until the next (possibly never) push.
                if reconcile_drops(slot, core, &mut last, &mut dropped_watermark, &mut backlog) {
                    terminate_on_fatal(slot, lane, core);
                    break;
                }
                // The queue is QUIET here (the timeout proves the
                // cursor sat at an empty channel): the stale backlog
                // has fully drained — disarm (the bot rounds 14+16:
                // receiving an event must NOT disarm, because older
                // states may sit behind it; only emptiness does).
                backlog = false;
                continue;
            }
            // SPLIT ARMS (the refactor pass's P1): engine death
            // (Disconnected, the slot still holding OUR connection)
            // retires the lane; a teardown-observed None belongs to
            // the CALLER's cleanup (disconnect/drain already own the
            // join AND the terminal publish — the bot round-28 P2:
            // publishing Disconnected here raced the caller's
            // after-join publication with a FALSE terminal while
            // teardown still ran). The engine-death arm ALSO yields
            // to a teardown that won the race (the bot round-34 P2):
            // an empty slot means the caller retired it mid-teardown
            // and owns the terminal publish — exit publishing
            // nothing.
            Some(Err(std::sync::mpsc::RecvTimeoutError::Disconnected)) => {
                // CLAIM-TO-PUBLISH (the bot round-36 P2): the
                // observation-only check could release the guard and a
                // teardown's retire() + Disconnecting landed before
                // this publish. The TAKE establishes ownership — only
                // the take that succeeds publishes the terminal; the
                // loser (a teardown emptied the slot) owns it.
                let claimed = slot.lock().ok().and_then(|mut guard| guard.take());
                if let Some(connection) = claimed {
                    connection.disconnect();
                    core.set_vpn_state(VpnState::Disconnected);
                    retire_lane(slot, lane);
                }
                break;
            }
            None => {
                // Teardown-observed: the caller publishes the terminal
                // state after its join — exit publishing nothing.
                break;
            }
        };
        match event {
            EngineEvent::State(state) => {
                // STALE-BACKLOG SUPPRESSION (the bot round-28 P2):
                // while recovery is armed, every queued State event is
                // PRE-DROP (older than the authoritative snapshot the
                // reconcile just published) — publishing one would
                // transiently misreport (an old Disconnected reading
                // as a real teardown). The quiet-cadence reconcile
                // re-publishes latest_state; the backlog disarms only
                // on a proven-empty queue.
                if backlog {
                    continue;
                }
                // RETIREMENT SUPPRESSION (the bot rounds 32+34+35
                // P2): the event was dequeued BEFORE the teardown
                // took the connection — publishing it now would
                // falsely revert the just-published Disconnecting to
                // an old Connecting/Connected while
                // disconnect_and_wait still runs (or leave a stale
                // state through a slow replacement setup). The guard
                // is held THROUGH the publish (the round-35 atom: the
                // round-34 shape dropped it after the check — a
                // retire-first teardown landed in that exact gap). A
                // retirement can now only land before the check
                // (stale — suppressed) or after the guard releases
                // (a genuinely newer transition).
                let guard = slot.lock();
                let retired = match &guard {
                    Ok(inner) => inner.as_ref().is_none(),
                    Err(_) => true,
                };
                if retired {
                    continue;
                }
                if let EngineConnectionState::Disconnected {
                    error: Some(ref detail),
                } = state.connection
                {
                    tracing::warn!(error = %detail, "the engine disconnected with an error");
                }
                let mapped = map_vpn_state(&state);
                if last.as_ref() != Some(&mapped) {
                    core.set_vpn_state(mapped);
                    last = Some(mapped);
                }
                drop(guard);
            }
            // The engine contract: the caller must close the
            // connection (the bot round's P2). Same for a retained
            // critical event recovered from a full queue — drain the
            // recovery slot on the quiet path too.
            EngineEvent::CertificateFatal => {
                terminate_on_fatal(slot, lane, core);
                break;
            }
            // The DELIVERED credential-invalid signal (the bot
            // round-32's second P2): the queue had capacity, so the
            // common path — the retained arm below already carries the
            // named ERROR line; the delivered arm was silently
            // discarded. Same named recovery surface on both paths;
            // the refresh itself stays the M6 auth-recovery lane's.
            EngineEvent::ApiError {
                refresh_token_invalid: true,
                ..
            } => {
                tracing::error!(
                    "LocalAgent reports the refresh token is invalid — reauthentication \
                     is required (the M6 auth-recovery lane owns the refresh; no provider \
                     is wired in this stack)"
                );
            }
            // Stats/refusals ride the engine's own recovery surfaces;
            // the daemon's stat broadcast is the M6 observability
            // lane.
            _ => {}
        }
        if reconcile_drops(slot, core, &mut last, &mut dropped_watermark, &mut backlog) {
            terminate_on_fatal(slot, lane, core);
            break;
        }
    }
}

/// Publishes the engine's authoritative state when the bounded queue
/// dropped pushes (the bot round's P2): `latest_state` stays current
/// even when the push lane did not.
fn reconcile_drops(
    slot: &ConnectionSlot,
    core: &CoreState,
    last: &mut Option<VpnState>,
    watermark: &mut u64,
    backlog: &mut bool,
) -> bool {
    let guard = match slot.lock() {
        Ok(guard) => guard,
        Err(_) => return false, // teardown took the connection
    };
    let Some(connection) = guard.as_ref() else {
        return false; // teardown took the connection
    };
    // The retained CRITICAL event drains here: a CertificateFatal
    // dropped by the full queue has no other delivery — and it is
    // PROPAGATED (the bot round-12 P2): the pump runs the same
    // teardown path as a directly delivered fatal (taking the event
    // and only logging it destroyed its sole recovery copy with the
    // tunnel still live).
    // EVERY retained critical is surfaced (the bot round-18 P2): a
    // ForkSelectorNeeded consumed here and dropped would lose the
    // engine-contract obligation (the consumer must provide a new
    // selector — the M6 Muon-refresh lane routes it); the terminal
    // fatal tears down HERE, the others WARN and ride the log until
    // that lane exists (silently discarding them is the bug).
    for critical in connection.take_critical_events() {
        match critical {
            EngineEvent::CertificateFatal => {
                tracing::warn!(
                    "a retained certificate-fatal surfaced from the drop lane — tearing the session down"
                );
                return true;
            }
            // The credential-invalid signal is NAMED distinctly (the
            // bot round-26 P2): it is the one retained control whose
            // loss leaves a failed session without reauthentication —
            // WARN at its own level so the operator (and the M6 auth
            // lane's log-based handoff until the wiring lands) sees
            // REAUTHORIZE, not a generic routed-event line.
            EngineEvent::ApiError {
                refresh_token_invalid: true,
                ..
            } => {
                tracing::error!(
                    "a retained invalid-credential ApiError surfaced from the drop lane — \
                     reauthentication is required (the M6 auth-recovery lane owns the \
                     refresh; no provider is wired in this stack)"
                );
            }
            other => {
                tracing::warn!(
                    ?other,
                    "a retained critical event surfaced from the drop lane — routed to the M6 lane"
                );
            }
        }
    }
    // WATERMARK-GATED (the refactor pass's P3): read the counter
    // first; the latest_state clone (a lock + a String/Vec-carrying
    // struct) happens only when drops actually moved — the common
    // quiet tick pays one load.
    // STALE-BACKLOG MODE (the bot rounds 14+16): once a drop is
    // observed, the queue holds PRE-DROP state events that can each
    // overwrite the reconciled core after this pass. The mode stays
    // armed until the queue is QUIET — this arm only runs on the
    // timeout path (an empty queue behind the cursor) or after a
    // received event (whose drain leaves the rest) — and every
    // invocation re-reconciles the core onto latest_state, so a
    // stale queued state is authoritative for at most one cadence
    // and never after the drain. The watermark only ARMS the mode.
    let dropped = connection.dropped_states();
    if dropped > *watermark {
        *watermark = dropped;
        *backlog = true;
    }
    if !*backlog {
        return false;
    }
    if let Some(state) = connection.latest_state() {
        let mapped = map_vpn_state(&state);
        if last.as_ref() != Some(&mapped) {
            core.set_vpn_state(mapped);
            *last = Some(mapped);
        }
    }
    false
}

/// Retires THIS pump's lane entry when the engine died on its own
/// (the bot round's P2): a reconnect may already have replaced the
/// lane — only the entry whose connection slot is OURS is retired.
fn retire_lane(slot: &ConnectionSlot, lane: &std::sync::Weak<Mutex<LaneState>>) {
    // Poison recovery matches the lane methods (the refactor
    // pass's P3): silently skipping retirement on a poisoned mutex
    // re-creates the stranded-owner state this function exists to
    // prevent.
    let Some(shared) = lane.upgrade() else {
        return; // a dropped lane needs no retirement (its drop IS one)
    };
    let mut lane = shared
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Ours only: a reconnect may already have replaced the entry —
    // the ptr_eq read decides WITHOUT a take-and-put-back dance.
    let ours = lane
        .active
        .as_ref()
        .is_some_and(|active| Arc::ptr_eq(&active.connection, slot));
    if ours {
        lane.active = None;
        lane.owner = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_gate_refuses_second_uid_and_allows_owner() {
        assert_eq!(gate_owner(None, 1000), Ok(()));
        assert_eq!(gate_owner(Some(1000), 1000), Ok(()));
        assert_eq!(
            gate_owner(Some(1000), 1001),
            Err(LaneRefusal::NotOwner { owner: 1000 })
        );
    }

    #[test]
    fn disconnect_refuses_through_every_window() {
        // The round-38 arm: drain takes the lane with no transition
        // flag armed — between its take and the join the lane reads
        // empty and unowned, and the admission decision must refuse
        // (the empty-lane idempotent success is ONLY for a lane no
        // window owns).
        assert_eq!(
            disconnect_refusal(&LaneState::default(), true),
            Some(LaneRefusal::Draining)
        );
        // Administrator first: a reconnect already in flight when the
        // drain armed still refuses as Draining — the drain loop owns
        // what happens to that lane next.
        let reconnecting = LaneState {
            reconnecting: true,
            ..LaneState::default()
        };
        assert_eq!(
            disconnect_refusal(&reconnecting, true),
            Some(LaneRefusal::Draining)
        );
        assert_eq!(
            disconnect_refusal(&reconnecting, false),
            Some(LaneRefusal::Reconnecting)
        );
        let disconnecting = LaneState {
            disconnecting: true,
            ..LaneState::default()
        };
        assert_eq!(
            disconnect_refusal(&disconnecting, false),
            Some(LaneRefusal::Disconnecting)
        );
        assert_eq!(disconnect_refusal(&LaneState::default(), false), None);
    }

    #[test]
    fn drain_waits_out_windows_and_concurrent_teardowns() {
        // An idle lane takes immediately: nothing runs, nothing to
        // wait for.
        assert!(!drain_waits(&LaneState::default()));
        // The round-28 user windows still gate the take.
        let reconnecting = LaneState {
            reconnecting: true,
            ..LaneState::default()
        };
        let disconnecting = LaneState {
            disconnecting: true,
            ..LaneState::default()
        };
        assert!(drain_waits(&reconnecting));
        assert!(drain_waits(&disconnecting));
        // The round-38 serialization: another drain's teardown is in
        // progress — the second caller WAITS for its completion
        // instead of observing the taken lane as idle and returning
        // while the first pump/TUN teardown still runs.
        let draining_now = LaneState {
            drain_in_progress: true,
            ..LaneState::default()
        };
        assert!(drain_waits(&draining_now));
    }

    #[test]
    fn engine_states_map_onto_the_frontend_state_machine() {
        let disconnected = EngineVpnState {
            interface_up: false,
            interface_error: None,
            connection: EngineConnectionState::Disconnected { error: None },
        };
        let connecting = EngineVpnState {
            interface_up: true,
            interface_error: None,
            connection: EngineConnectionState::Connecting {
                peer_ids: Vec::new(),
                waiting_for_network: false,
            },
        };
        let to_agent = EngineVpnState {
            interface_up: true,
            interface_error: None,
            connection: EngineConnectionState::ConnectingToAgent {
                peer: protonwire_protocol::engine::EnginePeerRef {
                    peer_id: "uk-42".to_owned(),
                    entry_ip: "185.159.158.1".parse().unwrap(),
                    protocol: protonwire_protocol::engine::EngineTransport::WireGuardUdp,
                    port: 51820,
                },
                wait: None,
            },
        };
        let connected = EngineVpnState {
            interface_up: true,
            interface_error: None,
            connection: EngineConnectionState::Connected {
                peer: protonwire_protocol::engine::EnginePeerRef {
                    peer_id: "uk-42".to_owned(),
                    entry_ip: "185.159.158.1".parse().unwrap(),
                    protocol: protonwire_protocol::engine::EngineTransport::WireGuardUdp,
                    port: 51820,
                },
                agent: None,
            },
        };
        assert_eq!(map_vpn_state(&disconnected), VpnState::Disconnected);
        assert_eq!(map_vpn_state(&connecting), VpnState::Connecting);
        // Agent negotiation is still Connecting to the frontend —
        // Connected means the whole session (FR-29's honest surface).
        assert_eq!(map_vpn_state(&to_agent), VpnState::Connecting);
        assert_eq!(map_vpn_state(&connected), VpnState::Connected);
    }
}
