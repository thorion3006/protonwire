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
//! land. The trait skeletons below are the S0 deliverable
//! (docs/spike-2026-08.md, "M2 S0"): they mirror the pinned Muon 2.6.1
//! surface, are deliberately synchronous and object-safe so core and the
//! daemon keep their synchronous trust boundary and the standard `&dyn`
//! seam-injection idiom, and carry no behavior yet. The S4 adapter
//! implements them over the Muon client; its tests fake at this seam for
//! state machines and at the environment/byte seam (a loopback
//! `http://` server behind a custom `Environment`) for wire fidelity.
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

/// Summary of an authenticated session, mirroring Muon's `LoginFlowData`
/// (`user_id`, `session_id`, `password_mode`). Entitlement data is
/// deliberately absent: Muon models none, and S8 owns that model
/// (spike memo Q8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// The Proton user ID.
    pub user_id: String,
    /// The auth-session UID Muon reports as `session_id`.
    pub session_id: String,
}

/// The WebAuthn challenge parameters Muon delivers alongside a 2FA
/// requirement (`muon_rest::auth::v4::fido2::Response` →
/// `authentication_options.public_key`). Reduced to what the FIDO2
/// ceremony consumes; S4 maps the upstream type into this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2Challenge {
    /// The challenge bytes from `PublicKeyCredentialRequestOptions`.
    pub challenge: Vec<u8>,
    /// Allowed credential IDs (the account's registered FIDO2 keys).
    pub allow_credentials: Vec<Vec<u8>>,
}

/// The typed second-factor challenge as exposed by pinned Muon: a TOTP
/// flag plus optional FIDO2 details (spike memo Q1). Muon's shape is a
/// closed two-bit field — anything beyond these two arms is by
/// definition an unknown challenge and never reaches this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// TOTP is enabled for the account.
    pub totp_enabled: bool,
    /// FIDO2 details when the account has registered keys.
    pub fido2: Option<Fido2Challenge>,
}

/// Stable reasons a login flow stops without a session. These feed the
/// S2 `RpcErrorCode` variants (`UpstreamCapabilityBlocked`,
/// `UnsupportedChallenge`); the strings are recorded in
/// `docs/official-parity.yaml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedReason {
    /// Human verification: no authorized public Muon surface.
    HumanVerification,
    /// Organization SSO: no authorized public Muon surface.
    OrganizationSso,
    /// Guest login: not exposed by pinned Muon on Linux.
    GuestLogin,
    /// Connection feedback: out of scope for the required flows.
    Feedback,
    /// A challenge shape pinned Muon cannot continue (e.g. recovery
    /// codes, which Muon 2.6.1 does not model).
    UnsupportedChallenge,
}

/// One step of a login-family flow, mirroring Muon's three-variant
/// `LoginFlow` (spike memo Q1): a completed session, a continuation
/// challenge, or a fail-closed stop. Never a silent retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginStep {
    /// The session is authenticated and stored; login is complete.
    Session(SessionInfo),
    /// A second factor is required before the session is usable.
    Challenge(Challenge),
    /// The flow has no authorized public continuation; the stable
    /// reason is carried for the client surfaces.
    Blocked(BlockedReason),
}

/// A WebAuthn assertion payload assembled by the client ceremony and
/// submitted through Muon's `POST /auth/v4/2fa` `FIDO2` arm. Base64
/// fields as on the wire (spike memo Q1); secret-handling (zeroize on
/// drop) lands with the S4 implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fido2Payload {
    /// `PublicKeyCredential.clientDataJSON`, base64.
    pub client_data: String,
    /// Authenticator data, base64.
    pub authenticator_data: String,
    /// Assertion signature, base64.
    pub signature: String,
    /// The credential ID used.
    pub credential_id: Vec<u8>,
}

/// An opaque, single-use child-session fork selector minted by
/// `AuthenticationApi::fork` (Muon's `POST /auth/v4/sessions/forks`).
/// A session-bearing secret: never logged, never persisted beside the
/// parent envelope, and never shared with ProTUN's `ApiSession` cache
/// (PRD 6.5, FR-7C). Spike memo Q9: Muon logs selectors at `info`, so
/// S1's suppression must cover the fork modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSelector(String);

impl ForkSelector {
    /// Wrap a selector value produced by Muon.
    pub fn new(selector: impl Into<String>) -> Self {
        Self(selector.into())
    }

    /// The selector value, for submission to `import_fork` or handoff to
    /// ProTUN LocalAgent.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The authentication surface core programs against (Milestone 2).
///
/// Synchronous and object-safe by design (spike memo Q3): the S4 adapter
/// bridges to the engine's async runtime internally so the daemon's
/// synchronous trust boundary and the `&dyn` injection idiom are
/// preserved. No implementations yet — this is the compile-checked S0
/// skeleton.
pub trait AuthenticationApi: Send + Sync {
    /// Current login status for the owning UID.
    fn login_status(&self) -> Result<LoginStatus, ApiError>;

    /// Begin SRP username/password login (`POST /auth/v4/info` then
    /// `POST /auth/v4`). Returns the next step: a session, a 2FA
    /// challenge, or a fail-closed stop.
    fn begin_login(&self, username: &str, password: &str) -> Result<LoginStep, ApiError>;

    /// Continue a login paused at the 2FA step with a TOTP code
    /// (`POST /auth/v4/2fa`, `TwoFactorCode` arm).
    fn submit_two_factor(&self, code: &str) -> Result<LoginStep, ApiError>;

    /// Continue a login paused at the 2FA step with a WebAuthn assertion
    /// (`POST /auth/v4/2fa`, `FIDO2` arm).
    fn submit_fido_payload(&self, payload: &Fido2Payload) -> Result<LoginStep, ApiError>;

    /// Force a token refresh (`Session::refresh_auth`). Automatic
    /// refresh-on-401 still happens inside Muon; this is the explicit
    /// pre-expiry path (FR-3).
    fn refresh(&self) -> Result<LoginStatus, ApiError>;

    /// Log out: best-effort remote `DELETE /auth/v4`, guaranteed local
    /// credential removal (FR-4). Muon's logout is infallible by design;
    /// transport failures are reported but never prevent local clearing.
    fn logout(&self) -> Result<(), ApiError>;

    /// Fork the authenticated session to a child identified by
    /// `child_id` (conventionally the app name, as `pvpnclient` does for
    /// LocalAgent) and return the one-time selector (spike memo Q5).
    fn fork(&self, child_id: &str) -> Result<ForkSelector, ApiError>;

    /// Import an externally forked session by selector
    /// (`GET /auth/v4/sessions/forks/{selector}`), the FR-7L
    /// external-session import path.
    fn import_fork(&self, selector: &ForkSelector) -> Result<LoginStep, ApiError>;
}

/// The outcome of a conditional server-catalog fetch (FR-13E). Muon has
/// no first-class ETag support; the adapter sends `If-None-Match` and
/// classifies 304 itself (spike memo Q4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogFetch {
    /// The catalog changed (or no ETag was supplied): the new revision
    /// tag, if the API returned one, and the raw catalog body. S6 parses
    /// this into the FR-9 model; the skeleton keeps bytes so no model is
    /// frozen before that unit.
    Changed {
        /// The response `ETag`, to persist for the next conditional
        /// request (FR-13B).
        etag: Option<String>,
        /// The raw catalog JSON body.
        body: Vec<u8>,
    },
    /// The stored revision is still current; freshness is updated
    /// without rewriting catalog data.
    NotModified,
}

/// Server-metadata retrieval through Muon (FR-8/FR-9). Every read
/// travels the Muon transport, including its alternative-routing path
/// (FR-13A); the three-hour single-flight policy lives in core's S7
/// scheduler, not here.
pub trait CatalogApi: Send + Sync {
    /// Fetch the server catalog, conditionally on the stored revision.
    fn fetch(&self, etag: Option<&str>) -> Result<CatalogFetch, ApiError>;
}

/// Adapter errors. Milestone 2 maps these onto structured codes including
/// the stable `blocked-upstream` refusals.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The required flow has no authorized public surface in the pinned
    /// Muon release (human verification, SSO, guest mode, feedback).
    #[error("blocked upstream: {0}")]
    BlockedUpstream(&'static str),
    /// The pinned Muon release cannot continue this challenge shape
    /// (e.g. recovery codes); fails closed with a stable code per
    /// FR-7L instead of approximating the flow.
    #[error("unsupported challenge: {0}")]
    UnsupportedChallenge(&'static str),
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

    #[test]
    fn unsupported_challenge_is_distinct_from_blocked_upstream() {
        let a = ApiError::UnsupportedChallenge("recovery-code");
        let b = ApiError::BlockedUpstream("human-verification");
        assert_ne!(a.to_string(), b.to_string());
    }

    #[test]
    fn fork_selector_stays_opaque() {
        let selector = ForkSelector::new("child-selector");
        assert_eq!(selector.as_str(), "child-selector");
    }
}
