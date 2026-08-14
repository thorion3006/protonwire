//! NAT-PMP port forwarding (PRD 7.10, Milestone 6).
//!
//! Port forwarding requires a paid plan, is incompatible with Moderate NAT
//! (validated in `protonwire-store`'s config and revalidated server-side),
//! and exposes a lease the daemon must renew and release cleanly. The
//! LocalAgent-mediated communication path arrives with Milestone 4's
//! LocalAgent integration; NAT-PMP itself with Milestone 6.

/// State of a port-forwarding lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// No lease exists.
    Inactive,
    /// A lease was requested and is pending.
    Requesting,
    /// A port is forwarded and the lease is healthy.
    Active {
        /// Forwarded external port.
        port: u16,
    },
    /// Renewal failed and the lease is expiring.
        Expiring,
}

/// The port-forwarding surface core programs against (Milestone 6).
pub trait PortForwardingService: Send + Sync {
    /// Current lease state.
    fn lease_state(&self) -> Result<LeaseState, PortForwardingError>;
}

/// Errors from the port-forwarding service.
#[derive(Debug, thiserror::Error)]
pub enum PortForwardingError {
    /// The account is not entitled to port forwarding.
    #[error("port forwarding requires a paid plan")]
    NotEntitled,
    /// Moderate NAT is active, which excludes port forwarding.
    #[error("port forwarding is incompatible with moderate NAT")]
    ModerateNatConflict,
    /// The NAT-PMP exchange failed.
    #[error("NAT-PMP failure: {0}")]
    Transport(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_states_are_distinct() {
        assert_ne!(LeaseState::Inactive, LeaseState::Requesting);
        assert_ne!(
            LeaseState::Active { port: 12345 },
            LeaseState::Expiring
        );
    }
}
