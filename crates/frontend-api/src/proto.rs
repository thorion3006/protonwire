//! Wire protocol messages shared by the daemon and every client.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::DaemonState;

/// Protocol version of the frontend API. Version 1 is the Milestone 1
/// foundation surface: hello handshake, ping, full state, connect/disconnect
/// stubs, and the event stream.
pub const PROTOCOL_VERSION: u32 = 1;

/// Identifies the kind of client at the other end of the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ClientSurface {
    /// The `protonwire` command-line interface.
    Cli,
    /// The `protonwire-tui` Ratatui interface.
    Tui,
    /// The `protonwire-gui` Tauri interface.
    Gui,
    /// Any other consumer of the documented IPC API (for example a test
    /// harness or future third-party integration).
    Other,
}

/// Information a client sends about itself during the hello handshake.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientInfo {
    /// Human-readable client name, for diagnostics only.
    pub name: String,
    /// Client version string, for diagnostics only.
    pub version: String,
    /// Which first-party surface (or `other`) the client implements.
    pub surface: ClientSurface,
}

impl ClientInfo {
    /// Returns a sanitized copy with control characters stripped and field
    /// lengths capped. The daemon applies this before storing or logging
    /// client-supplied identity, so hello fields cannot forge log lines.
    pub fn sanitized(&self) -> Self {
        fn clean(value: &str, max: usize) -> String {
            value
                .chars()
                .filter(|c| !c.is_control())
                .take(max)
                .collect()
        }
        Self {
            name: clean(&self.name, 64),
            version: clean(&self.version, 32),
            surface: self.surface,
        }
    }
}

/// The connection target grammar (PRD 9.2). The daemon validates and resolves
/// it; clients only construct it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum ConnectTarget {
    /// `protonwire connect fastest`
    Fastest,
    /// `protonwire connect random`
    Random,
    /// `connect country <ISO-3166-1-alpha-2>`
    Country { country: String },
    /// `connect state <STATE_OR_REGION>`
    State { state_or_region: String },
    /// `connect city <CITY_NAME>`
    City { city: String },
    /// `connect server <SERVER_NAME>`
    Server { server: String },
    /// `connect p2p` / `connect tor`
    Special { class: SpecialClass },
    /// `connect gateway <GATEWAY_NAME>`
    Gateway { gateway: String },
    /// `connect secure-core` with optional entry/exit country constraints.
    SecureCore {
        #[serde(skip_serializing_if = "Option::is_none")]
        entry_country: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit_country: Option<String>,
    },
    /// `connect group <namespaced-group-id>` (for example `proton:fastest-country`).
    Group { group_id: String },
    /// `connect profile <PROFILE_NAME>`
    Profile { profile: String },
}

/// Special server classes addressed without a name (PRD 9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SpecialClass {
    P2p,
    Tor,
}

/// A client → daemon message.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "data", rename_all = "kebab-case")]
pub enum ClientMessage {
    /// First message on a new connection. The daemon replies with
    /// [`ServerMessage::HelloAck`] or [`ServerMessage::HelloError`].
    Hello {
        /// Highest protocol version the client understands.
        protocol_version: u32,
        client: ClientInfo,
    },
    /// A request expecting exactly one [`ServerMessage::Response`].
    ///
    /// The wire shape is FLAT (recorded decision #1, 2026-08-17): the
    /// `method`/`params` tags of the inner [`Request`] are flattened
    /// directly into `data` beside the correlation id —
    /// `data: {id, method, params}` — instead of the M1 nesting
    /// `data: {id, request: {method, params}}`. Free until a client
    /// ships; deferring past the freeze would cost a major version.
    Request {
        /// Client-side correlation id, echoed in the response.
        id: u64,
        #[serde(flatten)]
        request: Request,
    },
}

/// A daemon → client message.
///
/// Adjacently tagged (`type` + `data`) so nested tagged enums such as
/// [`Response`] keep their own discriminant without colliding with this
/// one on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "data", rename_all = "kebab-case")]
pub enum ServerMessage {
    /// Successful handshake reply.
    HelloAck(HelloAck),
    /// Handshake refusal; the daemon closes the connection afterwards.
    HelloError(HelloError),
    /// Reply to a [`ClientMessage::Request`].
    Response(Response),
    /// A daemon-pushed event.
    Event(crate::event::EventEnvelope),
}

/// Successful handshake reply.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HelloAck {
    /// The protocol version the daemon will speak on this connection
    /// (≤ the client's requested version).
    pub protocol_version: u32,
    /// Daemon build version.
    pub daemon_version: String,
    /// Sequence number of the newest event emitted so far. A client that has
    /// seen a lower sequence performs a full-state resync via
    /// [`Request::GetState`].
    pub latest_event_seq: u64,
}

/// Handshake refusal with a machine-readable reason.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HelloError {
    /// Highest protocol version the daemon supports.
    pub supported_version: u32,
    /// Stable reason code, for example `unsupported-protocol-version`.
    pub reason: String,
}

/// Requests the daemon accepts (PRD FR-127). Milestone 1 implements
/// `Ping`/`GetState` end to end and returns a typed
/// [`RpcErrorCode::NotImplemented`] refusal for the connection lifecycle.
/// Milestone 2 S9 adds the servers/account/credential surface: the
/// catalog reads and scheduler-paced refresh, the login family over the
/// Muon adapter, the interactive credential submissions feeding the S5a
/// input source, and the account snapshot behind `account --json`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "method", content = "params", rename_all = "kebab-case")]
pub enum Request {
    /// Liveness probe; the daemon echoes the nonce.
    Ping {
        /// Arbitrary string echoed back in [`RequestResult::Pong`].
        nonce: String,
    },
    /// Full-state snapshot (the resynchronization primitive).
    GetState,
    /// Begin a connection. Refused until Milestone 4 wires the ProTUN engine.
    Connect { target: ConnectTarget },
    /// Tear down the active connection. Refused until Milestone 4.
    Disconnect,
    /// Stop the daemon. Requires administrator (UID 0) peer credentials.
    Shutdown,
    /// Serve the cached server catalog (FR-9/FR-10) — no upstream
    /// request; the daemon answers from the strict-loaded cache and
    /// reports `None` fields when nothing is cached yet.
    ServersList,
    /// Refresh the server catalog through the single-flight scheduler
    /// (FR-11/FR-13C). An early refresh is refused with
    /// [`RpcErrorCode::ConfirmationRequired`] carrying the typed
    /// [`ConfirmationRequirement`]; the confirmed retry echoes its
    /// single-use token here.
    ServersRefresh {
        /// The single-use confirmation token from a prior
        /// [`RpcErrorCode::ConfirmationRequired`] refusal, when
        /// confirming an early refresh (FR-13I).
        #[serde(skip_serializing_if = "Option::is_none")]
        confirmation_token: Option<String>,
    },
    /// Begin SRP username/password login (PRD 7.1). Refused with
    /// `invalid state` semantics (see [`RpcErrorCode::InvalidParams`])
    /// when a session already exists or a second-factor challenge is
    /// in progress — the client surfaces orchestrate the order.
    BeginLogin {
        /// The account username.
        username: SecretParam,
        /// The account password.
        password: SecretParam,
    },
    /// Continue a login paused at the 2FA step with a TOTP code
    /// (PRD 7.1). Only the 6–8 digit TOTP shape is submittable;
    /// recovery codes fail closed as
    /// [`RpcErrorCode::UnsupportedChallenge`].
    SubmitTwoFactor {
        /// The TOTP code.
        code: SecretParam,
    },
    /// Continue a login paused at the 2FA step with a WebAuthn/FIDO2
    /// assertion assembled by the client ceremony (PRD 7.1). Base64
    /// fields as on the wire.
    SubmitFidoPayload {
        /// `PublicKeyCredential.clientDataJSON`, base64.
        client_data: SecretParam,
        /// Authenticator data, base64.
        authenticator_data: SecretParam,
        /// Assertion signature, base64.
        signature: SecretParam,
        /// The credential ID used.
        credential_id: Vec<u8>,
    },
    /// Force a session token refresh (FR-3); invalidates any pending
    /// second-factor challenge.
    RefreshSession,
    /// Log out: best-effort remote teardown, guaranteed local
    /// credential removal (FR-4).
    Logout,
    /// Submit one credential value for the INTERACTIVE input source
    /// (FR-7F, S5a): the value lands in the daemon's in-memory input
    /// store keyed by short name (`session`, `username`, `password`)
    /// and is consumed by the source's read path. Peer-secret
    /// handling: the value crosses the daemon boundary into
    /// zeroizing, never-registry storage.
    SubmitCredential {
        /// The credential short name.
        name: String,
        /// The credential value.
        value: SecretParam,
    },
    /// The account snapshot behind `account --json` (FR-7H): login
    /// status, credential input source and its startup read, the
    /// configured writable store, and persistence health when the
    /// writable-store half reports one.
    GetAccount,
}

/// A secret value crossing the request boundary (a password, a TOTP
/// code, a credential value, a FIDO2 assertion field): serializes as a
/// plain JSON string — the local socket is the trusted transport — but
/// its `Debug` renders `[redacted]` so no log line, panic message, or
/// error formatter derived from a `{:?}` of a request ever carries it
/// (the S0/S4 `Fido2Payload` precedent, applied at the wire layer).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct SecretParam(String);

impl std::fmt::Debug for SecretParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretParam([redacted])")
    }
}

impl SecretParam {
    /// Wraps a secret value for a request.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Read access for the deliberate consumer (the daemon's ingress).
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// Successful request outcomes.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "result", content = "data", rename_all = "kebab-case")]
pub enum RequestResult {
    /// Reply to [`Request::Ping`].
    Pong { nonce: String },
    /// Reply to [`Request::GetState`].
    State { state: DaemonState },
    /// Reply to [`Request::Disconnect`] / [`Request::Shutdown`] /
    /// [`Request::Logout`] / [`Request::SubmitCredential`].
    Acknowledged,
    /// Reply to [`Request::ServersList`]: the cached catalog revision,
    /// served verbatim (FR-10 — the raw upstream body, never
    /// rewritten), or all-`None` fields when nothing is cached yet.
    Servers {
        /// The cached revision's `ETag`, for diagnostics.
        #[serde(skip_serializing_if = "Option::is_none")]
        etag: Option<String>,
        /// When this revision was fetched (Unix seconds); absent when
        /// no catalog is cached.
        #[serde(skip_serializing_if = "Option::is_none")]
        fetched_unix: Option<u64>,
        /// The raw catalog JSON body, byte-for-byte as cached.
        #[serde(skip_serializing_if = "Option::is_none")]
        body: Option<String>,
    },
    /// Reply to [`Request::ServersRefresh`]: the scheduler's report.
    ServersRefreshed {
        /// What the refresh did and what follows.
        report: ServersRefreshReport,
    },
    /// Reply to the login family ([`Request::BeginLogin`],
    /// [`Request::SubmitTwoFactor`], [`Request::SubmitFidoPayload`]):
    /// the next step of the flow, never a silent retry.
    LoginStep {
        /// The step's outcome.
        step: LoginOutcome,
    },
    /// Reply to [`Request::RefreshSession`]: the post-refresh status.
    LoginStatus {
        /// The session's login status after the refresh.
        status: SessionStatus,
    },
    /// Reply to [`Request::GetAccount`]: the account snapshot.
    Account {
        /// The account facts.
        account: AccountStatus,
    },
}

/// One step of a login-family flow on the wire (the S0/S4 adapter's
/// `LoginStep`): a completed session, a continuation challenge, or a
/// fail-closed stop with a stable reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "step", content = "data", rename_all = "kebab-case")]
pub enum LoginOutcome {
    /// The session is authenticated; login is complete.
    Session {
        /// The Proton user ID.
        user_id: String,
        /// The auth session ID.
        session_id: String,
    },
    /// A second factor is required before the session is usable.
    Challenge {
        /// TOTP is enabled for the account.
        totp_enabled: bool,
        /// FIDO2 ceremony parameters when the account has registered
        /// keys.
        #[serde(skip_serializing_if = "Option::is_none")]
        fido2: Option<Fido2ChallengeParams>,
    },
    /// The flow has no authorized public continuation; the stable
    /// reason is carried for the client surfaces (ER-17).
    Blocked {
        /// The stable refusal reason.
        reason: LoginBlockedReason,
    },
}

/// The WebAuthn ceremony parameters of a FIDO2 challenge (the wire
/// mirror of the adapter's reduced challenge).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Fido2ChallengeParams {
    /// The ceremony challenge bytes.
    pub challenge: Vec<u8>,
    /// Allowed credential IDs (the account's registered FIDO2 keys).
    pub allow_credentials: Vec<Vec<u8>>,
}

/// Stable reasons a login flow stops without a session (ER-17; the
/// strings are recorded in `docs/official-parity.yaml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum LoginBlockedReason {
    /// Human verification: no authorized public surface.
    HumanVerification,
    /// Organization SSO: no authorized public surface.
    OrganizationSso,
    /// Guest login: not exposed by the pinned adapter on Linux.
    GuestLogin,
    /// Connection feedback: out of scope for the required flows.
    Feedback,
    /// A challenge shape the pinned adapter cannot continue (for
    /// example recovery codes).
    UnsupportedChallenge,
}

/// Login status of the daemon's account session (the wire mirror of
/// the adapter's status).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SessionStatus {
    /// No session exists.
    LoggedOut,
    /// A session exists and is usable.
    LoggedIn,
    /// A session exists but must be refreshed before use.
    NeedsRefresh,
}

/// The scheduler's report for one manual refresh (FR-11/FR-13I): what
/// the refresh did, whether this caller joined an in-flight refresh,
/// and the pacing facts that follow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ServersRefreshReport {
    /// What the refresh did.
    pub outcome: ServersRefreshOutcome,
    /// `true` when this caller joined an already in-flight refresh
    /// (T-25 single-flight coalescing).
    pub coalesced: bool,
    /// The next automatic eligibility the refresh set (Unix seconds).
    pub next_eligible_unix: u64,
    /// The active suppression deadline after the refresh, if any
    /// (ER-16: no path may bypass it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_until_unix: Option<u64>,
}

/// What one catalog refresh did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", content = "data", rename_all = "kebab-case")]
pub enum ServersRefreshOutcome {
    /// A new catalog revision was fetched and committed.
    Changed {
        /// The new revision's `ETag`, when the API sent one.
        #[serde(skip_serializing_if = "Option::is_none")]
        etag: Option<String>,
    },
    /// The stored revision was still current (an ETag match).
    NotModified,
    /// The upstream rate-limited the refresh; the suppression
    /// deadline in the report governs the next attempt.
    RateLimited {
        /// The `Retry-After` delay the API supplied, if any
        /// (already clamped at the adapter's parse seam).
        #[serde(skip_serializing_if = "Option::is_none")]
        retry_after_seconds: Option<u64>,
    },
    /// The refresh failed; `reason` is a stable, never-secret
    /// description.
    Failed {
        /// Stable failure description.
        reason: String,
    },
}

/// The account snapshot behind `account --json` (FR-7H): never a
/// secret, never a fabricated fact — absent fields mean unknown or
/// not-yet-wired, per the S6 discipline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AccountStatus {
    /// The daemon account session's login status.
    pub login_status: SessionStatus,
    /// The resolved credential INPUT source (FR-7F).
    pub credential_source: CredentialSourceStatus,
    /// The configured WRITABLE store (the S5b/S5c half).
    pub writable_store: WritableStoreStatus,
    /// Persistence health, when the writable-store half reports one
    /// (ER-18). Absent until S5b/S5c wires the writable store — never
    /// fabricated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistence_health: Option<PersistenceHealth>,
}

/// The resolved credential input source (S5a's two arms).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "source", content = "data", rename_all = "kebab-case")]
pub enum CredentialSourceStatus {
    /// Values arrive over the IPC surface (the S9 interactive
    /// provider).
    Interactive,
    /// Read-only import from the systemd credentials directory
    /// (FR-7F/FR-7J).
    Systemd {
        /// The resolved `$CREDENTIALS_DIRECTORY`.
        directory: String,
        /// What the daemon's startup read of the preferred `session`
        /// credential found (recorded once, never re-read mid-run).
        startup_read: CredentialStartupRead,
    },
}

/// The recorded outcome of the daemon's startup read of the systemd
/// `session` credential — facts only, never value bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "read", content = "data", rename_all = "kebab-case")]
pub enum CredentialStartupRead {
    /// A current, integral FR-7C envelope was readable (the
    /// transactional import into the writable store is S5b's; this is
    /// the input-half fact).
    Read {
        /// The envelope's schema version.
        schema_version: u32,
    },
    /// The read refused; `reason` is the typed refusal's value-free
    /// summary (the recorded skip reason).
    Refused {
        /// Value-free refusal summary.
        reason: String,
    },
}

/// The configured writable-store facts (S5b/S5c own the resolution).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WritableStoreStatus {
    /// The declared `account.writable_session_store` vocabulary value.
    pub declared: String,
    /// The configured `account.writable_store_priority` order.
    pub priority: Vec<String>,
}

/// Writable-store persistence health (ER-18). Carried only when the
/// writable-store half is wired and reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PersistenceHealth {
    /// Restart persistence is intact.
    Healthy,
    /// Restart persistence is at risk; operations requiring durable
    /// login must fail. The reason is value-free.
    Unhealthy {
        /// Value-free failure summary.
        reason: String,
    },
}

/// Reply to a request.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Response {
    /// Successful outcome.
    Ok {
        /// Correlation id of the answered request.
        id: u64,
        result: RequestResult,
    },
    /// Failed outcome.
    Error {
        /// Correlation id of the answered request.
        id: u64,
        error: RpcError,
    },
}

impl Response {
    /// Correlation id of the request this response answers.
    pub fn id(&self) -> u64 {
        match self {
            Response::Ok { id, .. } | Response::Error { id, .. } => *id,
        }
    }
}

/// Machine-readable error taxonomy crossing the IPC boundary. Codes align
/// with the PRD 9.8 exit codes where one exists; clients map them directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RpcErrorCode {
    /// The requested capability is planned but not implemented yet.
    NotImplemented,
    /// The request parameters failed validation.
    InvalidParams,
    /// The client requested an unsupported protocol version.
    UnsupportedProtocol,
    /// The authenticated peer is not allowed to perform the request.
    PermissionDenied,
    /// No authenticated session exists for the peer's UID.
    NotAuthenticated,
    /// The account is not entitled to the requested capability.
    EntitlementMissing,
    /// No server satisfies the requested constraints.
    NoEligibleServer,
    /// The network is unavailable.
    NetworkUnavailable,
    /// The tunnel failed to establish or broke down.
    TunnelFailed,
    /// The kill switch could not be enforced.
    KillSwitchFailed,
    /// DNS could not be configured as requested.
    DnsConfigFailed,
    /// Firewall (nftables) configuration failed.
    FirewallFailed,
    /// Split-tunnel policy could not be applied.
    SplitTunnelFailed,
    /// Port forwarding failed.
    PortForwardingFailed,
    /// The daemon is busy and the request was not queued.
    DaemonBusy,
    /// The configuration failed validation.
    ConfigInvalid,
    /// The configured credential backend is unavailable.
    CredentialBackendUnavailable,
    /// No Secure Core route satisfies the request.
    SecureCoreUnavailable,
    /// The requested protocol is unavailable.
    ProtocolUnavailable,
    /// The requested capability has no verified public upstream flow
    /// (human verification, organization SSO, guest mode, feedback):
    /// fail closed with a stable code and remediation, never an
    /// automatic retry or an undocumented endpoint (ER-17).
    UpstreamCapabilityBlocked,
    /// The upstream presented an authentication challenge this daemon
    /// cannot continue — an unknown 2FA or verification shape (PRD §7).
    /// Fail closed: no retry, no untrusted URL, no approximation.
    UnsupportedChallenge,
    /// The request requires explicit user confirmation before it may
    /// proceed — the FR-11 early manual catalog refresh now, the FR-7D
    /// raw-password-storage and FR-7EA none-store confirmations later.
    /// `details` carries the typed [`ConfirmationRequirement`]
    /// envelope; a confirmed retry echoes its single-use token.
    ConfirmationRequired,
    /// The request was refused by a local suppression deadline or an
    /// upstream rate limit; the carried eligibility time governs the
    /// next attempt and no path may bypass it (ER-16).
    RateLimited,
    /// The writable credential store failed its health check: restart
    /// persistence is at risk and operations that require durable
    /// login must fail (ER-18).
    CredentialPersistenceUnhealthy,
    /// An internal daemon error without a more specific code.
    Internal,
}

/// Structured RPC error payload.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RpcError {
    /// Machine-readable code; never localized.
    pub code: RpcErrorCode,
    /// Human-readable diagnostic message, already redacted.
    pub message: String,
    /// Optional structured details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl RpcError {
    /// Builds an error with a code and message.
    pub fn new(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    /// Builds a [`RpcErrorCode::ConfirmationRequired`] refusal carrying
    /// the typed [`ConfirmationRequirement`] envelope in `details`.
    pub fn confirmation_required(
        message: impl Into<String>,
        requirement: ConfirmationRequirement,
    ) -> Self {
        Self {
            code: RpcErrorCode::ConfirmationRequired,
            message: message.into(),
            details: serde_json::to_value(&requirement).ok(),
        }
    }
}

/// The typed confirmation-requirement envelope (M2 S2): what a
/// [`RpcErrorCode::ConfirmationRequired`] refusal carries in
/// [`RpcError::details`] so a client can render the warning with the
/// scheduler's eligibility facts instead of parsing prose.
///
/// One shape serves every confirming flow — the FR-11 early manual
/// catalog refresh now and the FR-7D raw-password-storage /
/// FR-7EA none-store confirmations later; the `warning` text is the
/// flow's own. The `confirmation_token` placeholder fixes the wire
/// shape here; the S7 scheduler mints the real single-use token
/// (FR-13I: fresh per request, never stored as a preference).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConfirmationRequirement {
    /// Age of the protected resource when confirmation was demanded —
    /// for FR-11, the server catalog's age in seconds.
    pub catalog_age_seconds: u64,
    /// Unix time of the last recorded upstream request touching the
    /// resource; absent when none has been recorded yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_request_unix: Option<u64>,
    /// Earliest Unix time the request would be eligible WITHOUT
    /// confirmation (the greatest-of deadline the S7 scheduler
    /// computes).
    pub next_eligible_unix: u64,
    /// Already-redacted warning the client must display before
    /// confirming — the FR-11 rate-limit warning, the FR-7D
    /// raw-password warning.
    pub warning: String,
    /// Single-use confirmation token the confirmed request echoes
    /// (FR-13I). Placeholder shape in S2: an opaque non-empty string;
    /// S7 replaces the minting without changing the wire shape.
    pub confirmation_token: String,
}

impl ConfirmationRequirement {
    /// Decodes the envelope from a [`RpcError`]'s `details`, if the
    /// error carries one. Foreign or absent `details` decode to `None`
    /// rather than failing: `details` is an open JSON value, so a
    /// different payload is not a protocol violation for the reader.
    /// The decode is gated on the code too — a confirmation-SHAPED
    /// payload riding any other code is not a confirmation requirement
    /// and must not decode as one.
    pub fn from_error(error: &RpcError) -> Option<Self> {
        (error.code == RpcErrorCode::ConfirmationRequired)
            .then(|| serde_json::from_value(error.details.clone()?).ok())
            .flatten()
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", serde_plain_code(&self.code), self.message)
    }
}

impl std::error::Error for RpcError {}

/// Stable kebab-case rendering of a code, shared by `Display` and tests.
fn serde_plain_code(code: &RpcErrorCode) -> String {
    // Serialize with serde (kebab-case) and unquote; avoids a second name table.
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "rpc-error".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded decision #1 (2026-08-17, docs/m2-plan.md): the request
    /// nesting is FLAT — `data: {id, method, params}`, not `data: {id,
    /// request: {method, params}}`. Flattening is free until a client
    /// ships (nothing has shipped; distribution is license-blocked), and
    /// the round-6 reviewer recommended it before the protocol freezes.
    /// This pins the serialization direction.
    #[test]
    fn request_wire_shape_is_flat() {
        let msg = ClientMessage::Request {
            id: 7,
            request: Request::Ping {
                nonce: "abc".into(),
            },
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "type": "request",
                "data": {
                    "id": 7,
                    "method": "ping",
                    "params": { "nonce": "abc" }
                }
            })
        );
    }

    /// The flatten's other direction: a params-less method (GetState)
    /// deserializes from the flat shape with the correlation id intact.
    #[test]
    fn flat_request_shape_round_trips() {
        let json = serde_json::json!({
            "type": "request",
            "data": { "id": 9, "method": "get-state" }
        });
        match serde_json::from_value::<ClientMessage>(json).unwrap() {
            ClientMessage::Request { id, request } => {
                assert_eq!(id, 9);
                assert!(matches!(request, Request::GetState));
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    /// Characterization pin (green-by-design, per the round-6
    /// precedent): the flatten's deserialization side is open-world —
    /// serde's flatten buffers every key the outer variant does not
    /// name, and the internally tagged [`Request`] consumes only
    /// `method`/`params` from that buffer. So (a) unknown keys inside
    /// `data` are ignored, and (b) a frame carrying BOTH the flat keys
    /// and a legacy `request` wrapper decodes with the FLAT keys
    /// winning — the wrapper is just another ignored key. Pinned so a
    /// future legacy-compat re-acceptance of the wrapper (or a
    /// `deny_unknown_fields` tightening) cannot slip in unnoticed.
    #[test]
    fn flat_request_ignores_foreign_keys_and_the_legacy_wrapper() {
        let json = serde_json::json!({
            "type": "request",
            "data": {
                "id": 5,
                "method": "ping",
                "params": { "nonce": "n" },
                "foreign": { "anything": [1, 2] },
                "request": { "method": "shutdown", "params": null }
            }
        });
        match serde_json::from_value::<ClientMessage>(json).unwrap() {
            ClientMessage::Request { id, request } => {
                assert_eq!(id, 5);
                match request {
                    Request::Ping { nonce } => assert_eq!(nonce, "n"),
                    other => panic!("flat keys must win over a legacy wrapper: {other:?}"),
                }
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    /// Characterization pin (green-by-design): the legacy M1 nesting
    /// is REJECTED — with the flat `method` absent from `data`, the
    /// internally tagged enum has no discriminant and fails with the
    /// missing-field error, whatever the `request` wrapper carries.
    /// The flatten tolerates the wrapper's PRESENCE (previous pin) but
    /// never substitutes it for the flat keys.
    #[test]
    fn legacy_nested_request_shape_is_rejected() {
        let json = serde_json::json!({
            "type": "request",
            "data": { "id": 3, "request": { "method": "shutdown" } }
        });
        let err = serde_json::from_value::<ClientMessage>(json)
            .expect_err("the legacy nesting must not decode");
        assert!(
            err.to_string().contains("missing field `method`"),
            "the rejection must be the missing flat method: {err}"
        );
    }

    #[test]
    fn get_state_serializes_without_params() {
        let json = serde_json::to_value(Request::GetState).unwrap();
        assert_eq!(json, serde_json::json!({ "method": "get-state" }));
    }

    #[test]
    fn connect_target_country_round_trips() {
        let target = ConnectTarget::Country {
            country: "GB".into(),
        };
        let json = serde_json::to_value(&target).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "country", "value": { "country": "GB" } })
        );
        let back: ConnectTarget = serde_json::from_value(json).unwrap();
        assert_eq!(target, back);
    }

    #[test]
    fn error_codes_render_kebab_case() {
        assert_eq!(
            serde_plain_code(&RpcErrorCode::DnsConfigFailed),
            "dns-config-failed"
        );
    }

    /// M2 S2: the five new failure-mode codes render kebab-case like
    /// the rest of the taxonomy — clients map them off the stable
    /// string, never the debug name.
    #[test]
    fn m2_error_codes_render_kebab_case() {
        for (code, rendered) in [
            (
                RpcErrorCode::UpstreamCapabilityBlocked,
                "upstream-capability-blocked",
            ),
            (RpcErrorCode::UnsupportedChallenge, "unsupported-challenge"),
            (RpcErrorCode::ConfirmationRequired, "confirmation-required"),
            (RpcErrorCode::RateLimited, "rate-limited"),
            (
                RpcErrorCode::CredentialPersistenceUnhealthy,
                "credential-persistence-unhealthy",
            ),
        ] {
            assert_eq!(serde_plain_code(&code), rendered);
        }
    }

    /// M2 S2: the typed confirmation envelope rides
    /// `ConfirmationRequired` refusals in `details` and decodes back —
    /// one shape for the FR-11 servers-refresh confirmation now and the
    /// FR-7D raw-password-storage confirmation later. The token is the
    /// S7 placeholder shape (an opaque single-use string the scheduler
    /// will mint).
    #[test]
    fn confirmation_requirement_round_trips_through_error_details() {
        let requirement = ConfirmationRequirement {
            catalog_age_seconds: 3600,
            last_request_unix: Some(1_755_000_000),
            next_eligible_unix: 1_755_010_800,
            warning: "Unnecessary refreshes may be rate-limited or blocked by Proton.".into(),
            confirmation_token: "s7-placeholder".into(),
        };
        let error = RpcError::confirmation_required(
            "manual refresh before the next eligible time",
            requirement.clone(),
        );
        assert_eq!(error.code, RpcErrorCode::ConfirmationRequired);
        assert_eq!(
            ConfirmationRequirement::from_error(&error).as_ref(),
            Some(&requirement),
            "the envelope must decode from details"
        );

        // On the wire: the details carry the typed fields...
        let json = serde_json::to_value(&Response::Error { id: 4, error }).unwrap();
        assert_eq!(json["error"]["code"], "confirmation-required");
        assert_eq!(json["error"]["details"]["catalog_age_seconds"], 3600);
        assert_eq!(json["error"]["details"]["last_request_unix"], 1_755_000_000);
        assert_eq!(
            json["error"]["details"]["next_eligible_unix"],
            1_755_010_800
        );
        assert_eq!(
            json["error"]["details"]["confirmation_token"],
            "s7-placeholder"
        );

        // ...and a never-requested resource keeps `None` off the wire.
        let never_requested = ConfirmationRequirement {
            last_request_unix: None,
            ..requirement
        };
        let json = serde_json::to_value(RpcError::confirmation_required(
            "manual refresh",
            never_requested,
        ))
        .unwrap();
        assert!(
            json["details"].get("last_request_unix").is_none(),
            "an absent last request must not serialize: {json}"
        );

        // A foreign or absent details payload decodes to None, not a
        // protocol failure for the reader.
        assert!(
            ConfirmationRequirement::from_error(&RpcError::new(RpcErrorCode::Internal, "x"))
                .is_none()
        );
        // Present-but-unrelated details under the confirmation code
        // also decode to None (the shape, not just presence, decides).
        let unrelated = RpcError {
            details: Some(serde_json::json!({ "unrelated": true })),
            ..RpcError::new(RpcErrorCode::ConfirmationRequired, "x")
        };
        assert!(ConfirmationRequirement::from_error(&unrelated).is_none());
    }

    /// S2 rust-verdict Low: `from_error` must be gated on the error
    /// CODE, not just the details shape — `details` is an open JSON
    /// value that any code may carry, so a confirmation-SHAPED payload
    /// riding a foreign code is not a confirmation requirement. Red
    /// first: against the unguarded decode this arm returned `Some`
    /// (the shape parsed under `Internal`), observed before the guard
    /// landed.
    #[test]
    fn from_error_ignores_confirmation_details_under_a_foreign_code() {
        let requirement = ConfirmationRequirement {
            catalog_age_seconds: 60,
            last_request_unix: None,
            next_eligible_unix: 1_755_000_060,
            warning: "forged shape".into(),
            confirmation_token: "not-a-confirmation".into(),
        };
        let mut error = RpcError::new(RpcErrorCode::Internal, "unrelated failure");
        error.details = serde_json::to_value(&requirement).ok();
        assert!(
            ConfirmationRequirement::from_error(&error).is_none(),
            "a foreign code must not decode confirmation-shaped details: {}",
            serde_plain_code(&error.code)
        );
    }

    #[test]
    fn hello_handshake_round_trips() {
        let msg = ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            client: ClientInfo {
                name: "protonwire".into(),
                version: "0.1.0".into(),
                surface: ClientSurface::Cli,
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: ClientMessage = serde_json::from_str(&json).unwrap();
        match back {
            ClientMessage::Hello {
                protocol_version, ..
            } => {
                assert_eq!(protocol_version, PROTOCOL_VERSION)
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn client_info_sanitizes_control_characters_and_caps_length() {
        let info = ClientInfo {
            name: "fake\r\nAug 14 root: connection established by root".into(),
            version: "1.2.3\x1b[31m".into(),
            surface: ClientSurface::Other,
        };
        let clean = info.sanitized();
        assert!(!clean.name.contains('\n') && !clean.name.contains('\r'));
        assert!(!clean.version.contains('\x1b'));
        assert!(clean.name.chars().count() <= 64);
        let long = "x".repeat(200);
        assert_eq!(
            ClientInfo {
                name: long.clone(),
                version: long,
                surface: ClientSurface::Other,
            }
            .sanitized()
            .name
            .chars()
            .count(),
            64
        );
    }

    /// M2 S9: the servers/account/credential surface rides the flat
    /// request shape — `method` kebab-case, params beside the id, the
    /// confirmation token absent until a confirmed retry carries it.
    #[test]
    fn s9_request_methods_render_kebab_case() {
        let json = serde_json::to_value(&Request::ServersList).unwrap();
        assert_eq!(json, serde_json::json!({ "method": "servers-list" }));

        let early = serde_json::to_value(&Request::ServersRefresh {
            confirmation_token: None,
        })
        .unwrap();
        // Characterization (serde's tag+content shape): a variant WITH
        // fields always emits its `params` object, even when every
        // field is skip-serialized — the tokenless refresh is
        // `params: {}`, while the unit variants (ServersList, Logout,
        // ...) carry no params at all (pinned above).
        assert_eq!(
            early,
            serde_json::json!({ "method": "servers-refresh", "params": {} })
        );
        // And the encoding round-trips (the params-less encoding does
        // NOT decode — serde's tag+content requires the content key for
        // a variant with fields — so senders always emit `params`).
        match serde_json::from_value::<Request>(early).unwrap() {
            Request::ServersRefresh { confirmation_token } => {
                assert_eq!(confirmation_token, None)
            }
            other => panic!("unexpected: {other:?}"),
        }

        let confirmed = serde_json::to_value(&Request::ServersRefresh {
            confirmation_token: Some("tok".into()),
        })
        .unwrap();
        assert_eq!(
            confirmed,
            serde_json::json!({ "method": "servers-refresh", "params": { "confirmation_token": "tok" } })
        );

        for (request, method) in [
            (&Request::RefreshSession, "refresh-session"),
            (&Request::Logout, "logout"),
            (&Request::GetAccount, "get-account"),
        ] {
            assert_eq!(
                serde_json::to_value(request).unwrap()["method"],
                method,
                "{request:?}"
            );
        }
    }

    /// M2 S9: the secret-carrying request params serialize as plain
    /// strings (the local socket is the transport) but NEVER render
    /// through `Debug` — a log line, panic, or error formatter derived
    /// from `{:?}` of a request must not disclose them (the S4
    /// `Fido2Payload` precedent at the wire layer).
    #[test]
    fn secret_params_never_render_their_values() {
        let request = Request::BeginLogin {
            username: SecretParam::new("alice@example.com"),
            password: SecretParam::new("hunter2-wire-pin"),
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("hunter2-wire-pin"));
        assert!(!rendered.contains("alice@example.com"));
        assert!(rendered.contains("[redacted]"));

        // On the wire they are plain strings, and they round-trip.
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["params"]["password"], "hunter2-wire-pin");
        let back: Request = serde_json::from_value(json).unwrap();
        match back {
            Request::BeginLogin { username, password } => {
                assert_eq!(username.expose(), "alice@example.com");
                assert_eq!(password.expose(), "hunter2-wire-pin");
            }
            other => panic!("unexpected: {other:?}"),
        }

        let submit = Request::SubmitCredential {
            name: "session".into(),
            value: SecretParam::new("envelope-secret-bytes"),
        };
        let rendered = format!("{submit:?}");
        assert!(!rendered.contains("envelope-secret-bytes"));
        assert!(rendered.contains("[redacted]"));
    }

    /// M2 S9: the response-side wire shapes — the servers snapshot
    /// (absent fields stay off the wire when nothing is cached), the
    /// refresh report, the login steps, and the account snapshot's
    /// never-fabricated optional facts.
    #[test]
    fn s9_result_wire_shapes() {
        // Nothing cached: all-None fields stay off the wire.
        let empty = serde_json::to_value(RequestResult::Servers {
            etag: None,
            fetched_unix: None,
            body: None,
        })
        .unwrap();
        assert_eq!(empty["result"], "servers");
        assert_eq!(empty["data"].as_object().map(|o| o.len()), Some(0));

        let cached = serde_json::to_value(RequestResult::Servers {
            etag: Some("\"rev-42\"".into()),
            fetched_unix: Some(1_755_000_000),
            body: Some("{\"LogicalServers\":[]}".into()),
        })
        .unwrap();
        assert_eq!(cached["data"]["etag"], "\"rev-42\"");
        assert_eq!(cached["data"]["fetched_unix"], 1_755_000_000);

        // The refresh report mirrors the scheduler's facts.
        let report = ServersRefreshReport {
            outcome: ServersRefreshOutcome::RateLimited {
                retry_after_seconds: Some(120),
            },
            coalesced: false,
            next_eligible_unix: 1_755_010_800,
            suppression_until_unix: Some(1_755_010_800),
        };
        let json = serde_json::to_value(RequestResult::ServersRefreshed { report }).unwrap();
        assert_eq!(json["result"], "servers-refreshed");
        // The nested outcome is itself tag+content: the delay rides the
        // outcome's `data`.
        assert_eq!(json["data"]["report"]["outcome"]["outcome"], "rate-limited");
        assert_eq!(
            json["data"]["report"]["outcome"]["data"]["retry_after_seconds"],
            120
        );
        assert_eq!(json["data"]["report"]["coalesced"], false);
        assert_eq!(json["data"]["report"]["next_eligible_unix"], 1_755_010_800);
        let back: RequestResult = serde_json::from_value(json).unwrap();
        assert!(matches!(
            back,
            RequestResult::ServersRefreshed {
                report: ServersRefreshReport {
                    outcome: ServersRefreshOutcome::RateLimited {
                        retry_after_seconds: Some(120)
                    },
                    suppression_until_unix: Some(1_755_010_800),
                    ..
                }
            }
        ));

        // The login steps: session, challenge (fido2 absent off the
        // wire), and the stable blocked reasons. Each step is itself
        // tag+content, so its fields ride the step's `data`.
        let session = serde_json::to_value(RequestResult::LoginStep {
            step: LoginOutcome::Session {
                user_id: "uid-1".into(),
                session_id: "sid-1".into(),
            },
        })
        .unwrap();
        assert_eq!(session["result"], "login-step");
        assert_eq!(session["data"]["step"]["step"], "session");
        assert_eq!(session["data"]["step"]["data"]["user_id"], "uid-1");
        let challenge = serde_json::to_value(RequestResult::LoginStep {
            step: LoginOutcome::Challenge {
                totp_enabled: true,
                fido2: None,
            },
        })
        .unwrap();
        assert_eq!(challenge["data"]["step"]["step"], "challenge");
        assert_eq!(challenge["data"]["step"]["data"]["totp_enabled"], true);
        assert!(challenge["data"]["step"]["data"].get("fido2").is_none());
        for (reason, rendered) in [
            (LoginBlockedReason::HumanVerification, "human-verification"),
            (
                LoginBlockedReason::UnsupportedChallenge,
                "unsupported-challenge",
            ),
        ] {
            assert_eq!(
                serde_json::to_value(reason).unwrap(),
                rendered,
                "blocked reasons render kebab-case"
            );
        }

        // The account snapshot: absent persistence health stays off
        // the wire (never fabricated); the systemd arm carries the
        // startup-read facts.
        let account = serde_json::to_value(RequestResult::Account {
            account: AccountStatus {
                login_status: SessionStatus::LoggedOut,
                credential_source: CredentialSourceStatus::Systemd {
                    directory: "/run/credentials/protonwire.service".into(),
                    startup_read: CredentialStartupRead::Refused {
                        reason: "credential `session` is missing".into(),
                    },
                },
                writable_store: WritableStoreStatus {
                    declared: "auto".into(),
                    priority: vec!["keyring".into(), "encrypted-local".into()],
                },
                persistence_health: None,
            },
        })
        .unwrap();
        assert_eq!(account["result"], "account");
        let data = &account["data"]["account"];
        assert_eq!(data["login_status"], "logged-out");
        assert_eq!(data["credential_source"]["source"], "systemd");
        assert_eq!(
            data["credential_source"]["data"]["startup_read"]["read"],
            "refused"
        );
        assert_eq!(data["writable_store"]["declared"], "auto");
        assert!(data.get("persistence_health").is_none());
    }
}
