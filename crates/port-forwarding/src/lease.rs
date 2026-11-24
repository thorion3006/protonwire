//! The NAT-PMP lease state machine (T-40): pure, clock-injected, no
//! I/O — the transport feeds it observations and it decides the next
//! action and deadline.
//!
//! The lifecycle (FR-90/91): REQUEST after tunnel establishment →
//! ACTIVE (a public port mapped, renewal scheduled at half the
//! server-declared lifetime) → the transport renews before that
//! deadline → ACTIVE again; three consecutive renewal failures (or an
//! explicit release) → EXPIRING → INACTIVE. Every transition returns
//! the [`Action`] the caller owes the transport, so the FSM itself
//! never touches a socket.

use std::time::{Duration, Instant};

/// The lease's phase, mirrored in status (FR-92: the active port is
/// shown) and in the T-39/features surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// No lease exists.
    Inactive,
    /// A mapping request is in flight.
    Requesting,
    /// A port is mapped and the lease is healthy.
    Active { port: u16 },
    /// Renewals are failing; the mapping dies at the server's
    /// lifetime horizon.
    Expiring { port: u16, misses: u8 },
}

/// What the FSM owes the transport after an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send a NAT-PMP public-port request (opcode 2) to the gateway.
    Request,
    /// Send a renewal for this port.
    Renew { port: u16 },
    /// Send a release (lifetime 0) for this port.
    Release { port: u16 },
    /// Nothing to send; wake again at the returned deadline.
    Wait { until: Instant },
}

/// A successful NAT-PMP mapping answer from the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// The external port the gateway assigned (may differ from the
    /// requested one).
    pub public_port: u16,
    /// The server-declared lease lifetime.
    pub lifetime: Duration,
    /// The gateway's epoch seconds at the answer (renewal alignment).
    pub gateway_epoch: u32,
}

/// Three consecutive renewal failures end the lease (the FSM's
/// liveness bound — the mapping expires server-side at the declared
/// lifetime regardless).
const MAX_RENEWAL_MISSES: u8 = 3;

/// Renewals are scheduled at half the declared lifetime (FR-91's
/// "before expiry" with one full retry window in hand).
fn renewal_deadline(now: Instant, lifetime: Duration) -> Instant {
    now + lifetime / 2
}

/// The lease FSM. Created fresh per connection; driven by the events
/// below. The clock enters as `now: Instant` parameters — tests own
/// time completely.
#[derive(Debug, Clone)]
pub struct LeaseFsm {
    state: LeaseState,
    /// The pending renewal deadline while ACTIVE.
    renew_at: Option<Instant>,
}

impl LeaseFsm {
    /// A fresh FSM: INACTIVE, nothing owed.
    pub fn new() -> Self {
        Self {
            state: LeaseState::Inactive,
            renew_at: None,
        }
    }

    /// The current phase.
    pub fn state(&self) -> LeaseState {
        self.state
    }

    /// The first action after the tunnel is established and the
    /// feature is on (FR-90): ask the gateway for a mapping.
    pub fn start(&mut self) -> Action {
        self.state = LeaseState::Requesting;
        Action::Request
    }

    /// The gateway answered the request (or a renewal) with a
    /// mapping: the lease is ACTIVE and the renewal is scheduled at
    /// half the declared lifetime.
    pub fn mapped(&mut self, mapping: Mapping, now: Instant) -> Action {
        self.state = LeaseState::Active {
            port: mapping.public_port,
        };
        self.renew_at = Some(renewal_deadline(now, mapping.lifetime));
        Action::Wait {
            until: self.renew_at.expect("just set"),
        }
    }

    /// The renewal deadline passed (or the transport woke early): if
    /// the lease is ACTIVE this is the renewal send; an idle FSM owes
    /// nothing.
    pub fn tick(&mut self, now: Instant) -> Option<Action> {
        match self.state {
            LeaseState::Active { port }
                if self.renew_at.is_some_and(|deadline| now >= deadline) =>
            {
                Some(Action::Renew { port })
            }
            _ => None,
        }
    }

    /// A renewal ANSWER arrived: a mapping re-arms the lease; an
    /// error consumes a miss — three consecutive misses end the
    /// lease (EXPIRING, then the release send to be safe).
    pub fn renewal_outcome(
        &mut self,
        outcome: Result<Mapping, ()>,
        now: Instant,
    ) -> Option<Action> {
        match (outcome, self.state) {
            (Ok(mapping), LeaseState::Active { .. } | LeaseState::Expiring { .. }) => {
                Some(self.mapped(mapping, now))
            }
            (Err(()), LeaseState::Active { port, .. }) => {
                let misses = 1;
                if misses >= MAX_RENEWAL_MISSES {
                    self.state = LeaseState::Inactive;
                    self.renew_at = None;
                    Some(Action::Release { port })
                } else {
                    self.state = LeaseState::Expiring { port, misses };
                    self.renew_at = Some(now + Duration::from_secs(5));
                    Some(Action::Wait {
                        until: self.renew_at.expect("just set"),
                    })
                }
            }
            (Err(()), LeaseState::Expiring { port, misses }) => {
                let misses = misses + 1;
                if misses >= MAX_RENEWAL_MISSES {
                    self.state = LeaseState::Inactive;
                    self.renew_at = None;
                    Some(Action::Release { port })
                } else {
                    self.state = LeaseState::Expiring { port, misses };
                    self.renew_at = Some(now + Duration::from_secs(5));
                    Some(Action::Wait {
                        until: self.renew_at.expect("just set"),
                    })
                }
            }
            _ => None,
        }
    }

    /// The user (or teardown) releases the lease: the release send is
    /// owed and the FSM goes INACTIVE immediately.
    pub fn release(&mut self) -> Option<Action> {
        match self.state {
            LeaseState::Active { port } | LeaseState::Expiring { port, .. } => {
                self.state = LeaseState::Inactive;
                self.renew_at = None;
                Some(Action::Release { port })
            }
            _ => None,
        }
    }

    /// The tunnel died (FR-90's "after tunnel establishment" inverse):
    /// the mapping is meaningless without it. No release send — the
    /// gateway's own lifetime expires the mapping.
    pub fn tunnel_down(&mut self) {
        self.state = LeaseState::Inactive;
        self.renew_at = None;
    }
}

impl Default for LeaseFsm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // std::time::Instant has no ZERO constant — each test anchors to a
    // single captured base instant and reasons in DELTAS from it, which
    // is exactly how the FSM is driven in production (now-relative).

    /// T-40 (the happy path): start → Request; the mapping lands →
    /// ACTIVE with a renewal scheduled at HALF the lifetime; tick
    /// before the deadline owes nothing; tick at the deadline owes a
    /// renewal; the renewal answer re-arms at the new half-life.
    #[test]
    fn t40_the_lease_lifecycle_schedules_renewal_at_half_life() {
        let t0 = Instant::now();
        let mut fsm = LeaseFsm::new();
        assert_eq!(fsm.state(), LeaseState::Inactive);
        assert_eq!(fsm.start(), Action::Request);
        assert_eq!(fsm.state(), LeaseState::Requesting);

        // The gateway maps 61234 for 7200 s: renewal at t0 + 3600 s.
        let mapping = Mapping {
            public_port: 61234,
            lifetime: Duration::from_secs(7200),
            gateway_epoch: 1_000_000,
        };
        let action = fsm.mapped(mapping, t0);
        assert_eq!(
            action,
            Action::Wait {
                until: t0 + Duration::from_secs(3600)
            }
        );
        assert_eq!(fsm.state(), LeaseState::Active { port: 61234 });

        // Before the deadline: nothing owed.
        assert_eq!(fsm.tick(t0 + Duration::from_secs(3599)), None);
        // At the deadline: the renewal send.
        assert_eq!(
            fsm.tick(t0 + Duration::from_secs(3600)),
            Some(Action::Renew { port: 61234 })
        );
        // The renewal lands with a new lifetime: re-armed from NOW.
        let action = fsm
            .renewal_outcome(
                Ok(Mapping {
                    public_port: 61234,
                    lifetime: Duration::from_secs(7200),
                    gateway_epoch: 1_000_360,
                }),
                t0 + Duration::from_secs(3601),
            )
            .expect("a renewal answer re-arms the wait");
        assert_eq!(
            action,
            Action::Wait {
                until: t0 + Duration::from_secs(3601) + Duration::from_secs(3600)
            }
        );
        assert_eq!(fsm.state(), LeaseState::Active { port: 61234 });
    }

    /// Three consecutive renewal failures end the lease: ACTIVE →
    /// EXPIRING (miss 1) → EXPIRING (miss 2) → INACTIVE + release
    /// (miss 3 — send a release anyway, the gateway may still hold
    /// the mapping).
    #[test]
    fn three_renewal_failures_expire_the_lease_with_a_final_release() {
        let t0 = Instant::now();
        let mut fsm = LeaseFsm::new();
        fsm.start();
        fsm.mapped(
            Mapping {
                public_port: 50000,
                lifetime: Duration::from_secs(7200),
                gateway_epoch: 1,
            },
            t0,
        );

        // Miss 1 → EXPIRING, retry in 5 s.
        let action = fsm
            .renewal_outcome(Err(()), t0 + Duration::from_secs(3600))
            .expect("miss 1 schedules a retry");
        assert_eq!(
            action,
            Action::Wait {
                until: t0 + Duration::from_secs(3605)
            }
        );
        assert_eq!(
            fsm.state(),
            LeaseState::Expiring {
                port: 50000,
                misses: 1
            }
        );

        // Miss 2 → EXPIRING, misses accumulate.
        let action = fsm
            .renewal_outcome(Err(()), t0 + Duration::from_secs(3610))
            .expect("miss 2 schedules a retry");
        assert_eq!(
            action,
            Action::Wait {
                until: t0 + Duration::from_secs(3615)
            }
        );
        assert_eq!(
            fsm.state(),
            LeaseState::Expiring {
                port: 50000,
                misses: 2
            }
        );

        // Miss 3 → INACTIVE + the final release send.
        assert_eq!(
            fsm.renewal_outcome(Err(()), t0 + Duration::from_secs(3620)),
            Some(Action::Release { port: 50000 })
        );
        assert_eq!(fsm.state(), LeaseState::Inactive);
    }

    /// A renewal that SUCCEEDS after a miss recovers to ACTIVE
    /// (misses don't accumulate forever against a recovered lease —
    /// the EXPIRING state answers a successful renewal with a fresh
    /// half-life wait).
    #[test]
    fn a_successful_renewal_recovers_from_expiring() {
        let t0 = Instant::now();
        let mut fsm = LeaseFsm::new();
        fsm.start();
        fsm.mapped(
            Mapping {
                public_port: 50001,
                lifetime: Duration::from_secs(7200),
                gateway_epoch: 1,
            },
            t0,
        );
        let _ = fsm.renewal_outcome(Err(()), t0 + Duration::from_secs(3600));
        assert!(matches!(fsm.state(), LeaseState::Expiring { .. }));

        let action = fsm
            .renewal_outcome(
                Ok(Mapping {
                    public_port: 50001,
                    lifetime: Duration::from_secs(7200),
                    gateway_epoch: 2,
                }),
                t0 + Duration::from_secs(3610),
            )
            .expect("the recovery re-arms");
        assert_eq!(
            action,
            Action::Wait {
                until: t0 + Duration::from_secs(3610) + Duration::from_secs(3600)
            }
        );
        assert_eq!(fsm.state(), LeaseState::Active { port: 50001 });
    }

    /// Explicit release: ACTIVE → INACTIVE + the release send;
    /// releasing an INACTIVE lease owes nothing (idempotent).
    #[test]
    fn release_is_explicit_and_idempotent() {
        let t0 = Instant::now();
        let mut fsm = LeaseFsm::new();
        assert_eq!(fsm.release(), None, "nothing to release while INACTIVE");
        fsm.start();
        fsm.mapped(
            Mapping {
                public_port: 50002,
                lifetime: Duration::from_secs(7200),
                gateway_epoch: 1,
            },
            t0,
        );
        assert_eq!(fsm.release(), Some(Action::Release { port: 50002 }));
        assert_eq!(fsm.state(), LeaseState::Inactive);
        assert_eq!(fsm.release(), None);
    }

    /// The tunnel died: INACTIVE with no release send (the gateway's
    /// lifetime expires the mapping); a subsequent start restarts the
    /// lifecycle cleanly.
    #[test]
    fn tunnel_down_resets_without_a_release_and_start_restarts() {
        let t0 = Instant::now();
        let mut fsm = LeaseFsm::new();
        fsm.start();
        fsm.mapped(
            Mapping {
                public_port: 50003,
                lifetime: Duration::from_secs(7200),
                gateway_epoch: 1,
            },
            t0,
        );
        fsm.tunnel_down();
        assert_eq!(fsm.state(), LeaseState::Inactive);
        assert_eq!(fsm.tick(t0 + Duration::from_secs(7200)), None);
        // Restart: a clean REQUEST.
        assert_eq!(fsm.start(), Action::Request);
        assert_eq!(fsm.state(), LeaseState::Requesting);
    }

    /// Tick on a non-ACTIVE lease owes nothing (a REQUESTING lease
    /// that never got an answer has no deadline to fire).
    #[test]
    fn tick_owes_nothing_outside_active() {
        let t0 = Instant::now();
        let mut fsm = LeaseFsm::new();
        assert_eq!(fsm.tick(t0 + Duration::from_secs(999)), None);
        let _ = fsm.start();
        assert_eq!(fsm.tick(t0 + Duration::from_secs(999)), None);
    }
}
