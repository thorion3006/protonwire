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

use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

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
}

#[derive(Default)]
struct LaneState {
    active: Option<ActiveLane>,
    owner: Option<u32>,
}

/// The lane. Construct once at daemon startup with the production
/// mode; the engine inside is stateless configuration.
pub struct ConnectionLane {
    engine: ConnectionEngine,
    facade: Arc<PersistenceFacade>,
    core: Arc<CoreState>,
    state: Mutex<LaneState>,
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
            state: Mutex::new(LaneState::default()),
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
        // Reconnect by the owner: tear the previous session down first
        // (FR-28's reconnect IS a fresh connection — peer rotation on
        // a LIVE session is update_peers, the engine's own surface).
        if let Some(active) = lane.active.take() {
            active.teardown();
        }
        // The old owner is cleared BEFORE the engine attempt: a FAILED
        // reconnect must not leave a phantom owner locking every other
        // UID out with no tunnel existing (the gate's P2 — no state
        // commits on failing paths; the owner is recorded only after a
        // confirmed start).
        lane.owner = None;
        let connection = self.engine.connect(
            params,
            Box::new(SharedFacadeCache(Arc::clone(&self.facade))),
        )?;
        let slot: ConnectionSlot = Arc::new(Mutex::new(Some(connection)));
        let core = Arc::clone(&self.core);
        let pump_slot = Arc::clone(&slot);
        let pump = std::thread::spawn(move || pump_events(&pump_slot, &core));
        lane.active = Some(ActiveLane {
            connection: slot,
            pump,
        });
        lane.owner = Some(uid);
        Ok(())
    }

    /// Tears the active connection down. Only the owner (a disconnect
    /// with no active connection is an idempotent success).
    pub fn disconnect(&self, uid: u32) -> Result<(), LaneRefusal> {
        let mut lane = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        gate_owner(lane.owner, uid)?;
        if let Some(active) = lane.active.take() {
            active.teardown();
        }
        lane.owner = None;
        Ok(())
    }

    /// Daemon shutdown: unconditional teardown (the administrator's
    /// lane, not a user's — no owner gate), blocking until the pump
    /// exits so no event races the IPC socket's close.
    pub fn drain(&self) {
        self.draining.store(true, Ordering::SeqCst);
        let mut lane = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(active) = lane.active.take() {
            active.teardown();
        }
        lane.owner = None;
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
/// or the engine died on its own; either way the TERMINAL state is
/// published, never left stranded at Connecting/Connected — the
/// gate's P2). Runs on its own thread; every step is non-blocking on
/// the engine side.
fn pump_events(slot: &ConnectionSlot, core: &CoreState) {
    let mut last: Option<VpnState> = None;
    loop {
        let received = slot.lock().ok().and_then(|mut guard| {
            guard
                .as_mut()
                .map(|connection| connection.events().recv_timeout(PUMP_POLL))
        });
        let event = match received {
            Some(Ok(event)) => event,
            Some(Err(std::sync::mpsc::RecvTimeoutError::Timeout)) => continue,
            Some(Err(std::sync::mpsc::RecvTimeoutError::Disconnected)) | None => {
                // The engine died on its own (or teardown took the
                // connection): the process-wide state machine must
                // not strand at the last live state.
                core.set_vpn_state(VpnState::Disconnected);
                break;
            }
        };
        let EngineEvent::State(state) = event else {
            continue; // stats/refusals ride the engine's own surface;
            // the daemon's stat broadcast is the M6
            // observability lane
        };
        if let EngineConnectionState::Disconnected { error: Some(ref detail) } = state.connection {
            tracing::warn!(error = %detail, "the engine disconnected with an error");
        }
        let mapped = map_vpn_state(&state);
        if last.as_ref() != Some(&mapped) {
            core.set_vpn_state(mapped);
            last = Some(mapped);
        }
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
                peer_id: "uk-42".to_owned(),
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
