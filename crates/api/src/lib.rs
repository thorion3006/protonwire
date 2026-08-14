//! Muon adapter — the required Proton API transport (PRD 6.5).
//!
//! Muon is the *only* production path for SRP login, TOTP/FIDO2 payload
//! submission, session state, cookies, normal Proton API requests,
//! alternative routing, and session-fork flows. ProtonWire-owned typed
//! models may describe endpoints Muon does not model, but they must still
//! travel through Muon rather than a second Proton HTTP/auth stack.
//!
//! The pinned crate is re-exported so the workspace lockfile governs its
//! resolution and so this crate is the single place upstream API changes
//! land. The adapter itself arrives in Milestone 2:
//!
//! * SRP login, TOTP/recovery-code, FIDO2/WebAuthn payload, refresh/logout
//! * forking and alternative routing
//! * fail-closed, stable-coded refusals for human verification, SSO, guest
//!   login, and connection feedback (`blocked-upstream` in
//!   `docs/official-parity.yaml`)
//! * server metadata retrieval and user-location capture

pub use muon;

/// Authentication capabilities the adapter must expose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginStatus {
    /// No session exists for the UID.
    LoggedOut,
    /// A session exists and is usable.
    LoggedIn,
    /// A session exists but must be refreshed before use.
    NeedsRefresh,
}

/// The authentication surface core programs against (Milestone 2).
pub trait AuthenticationApi: Send + Sync {
    /// Current login status for the owning UID.
    fn login_status(&self) -> Result<LoginStatus, ApiError>;
}

/// Adapter errors. Milestone 2 maps these onto structured codes including
/// the stable `blocked-upstream` refusals.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The required flow has no authorized public surface in the pinned
    /// Muon release (human verification, SSO, guest mode, feedback).
    #[error("blocked upstream: {0}")]
    BlockedUpstream(&'static str),
    /// The Proton API transport failed.
    #[error("transport failure: {0}")]
    Transport(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_upstream_is_distinct_from_transport_failure() {
        let a = ApiError::BlockedUpstream("human-verification");
        let b = ApiError::Transport("timeout".into());
        assert_ne!(a.to_string(), b.to_string());
    }
}
