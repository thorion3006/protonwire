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
    /// Resolve a selection WITHOUT connecting (M3 U6, FR-23T): the
    /// daemon composes the cached catalog (strict load), the S8
    /// entitlement seams, FR-23Q's physical-country sources, and the
    /// bounded on-demand prober, then answers with the full
    /// provenance-carrying result. A pure query — no tunnel state
    /// changes, no events (FR-123's connection-group status fields
    /// ride the M4 connection transition, not a query).
    Select {
        /// The connection-target grammar (shared with `connect`).
        target: ConnectTarget,
        /// The §9.3 selection-plane modifiers.
        modifiers: SelectionModifiers,
    },
    /// The built-in connection-group catalog (M3 U6, FR-23I/U): served
    /// from core's generated registry — no network request, no
    /// hard-coded client lists. Each entry carries its FR-23S
    /// availability evaluation against the current cached catalog.
    GroupsList,
    /// One group's full definition (FR-23U `group show`).
    GroupShow {
        /// The stable namespaced group id.
        id: String,
    },
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
    /// Reply to [`Request::Select`]: the resolved selection with
    /// FR-23T's provenance fields end to end. The winner is the
    /// best-ranked candidate; a successful reply always carries one
    /// (every refusal path is an [`RpcError`]). Boxed: the full
    /// provenance set is large, and this result enum travels through
    /// the session writer — indirection keeps every other variant
    /// cheap.
    Selected {
        /// The selection result.
        result: Box<SelectionResult>,
    },
    /// Reply to [`Request::GroupsList`]: the built-in catalog with the
    /// registry's provenance stamps and per-group availability.
    Groups {
        /// The full group catalog (every entry, registry order).
        catalog: GroupsCatalog,
    },
    /// Reply to [`Request::GroupShow`]: one group's full definition.
    /// Boxed alongside [`RequestResult::Selected`] — the detail
    /// document's string set is large, and this enum travels cloned.
    Group {
        /// The group's details.
        group: Box<GroupDetails>,
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

// ---------------------------------------------------------------------------
// The U6 selection/groups wire family (M3 PR-4; FR-23T/FR-23U/FR-23S)
// ---------------------------------------------------------------------------

/// A selection-plane feature constraint (§9.3's `--require` family and
/// the optional slot the balanced feature-match term consumes). The
/// forbidden throughput signals do not exist here — `speed` is rejected
/// at the ranking-mode vocabulary, never modeled as a feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SelectionFeature {
    /// P2P-friendly (catalog bit).
    P2p,
    /// Tor over VPN (catalog bit).
    Tor,
    /// Secure Core (catalog bit; under a Standard-fleet target this is
    /// the typed contradiction — Secure Core connectivity is a routed
    /// TARGET).
    SecureCore,
    /// Streaming-capable where exposed (catalog bit).
    Streaming,
    /// IPv6-capable (catalog bit).
    Ipv6,
    /// Port-forwarding-capable (NO catalog bit: evaluates against the
    /// daemon-composed entitlement and per-server capability seams;
    /// FR-23H/FR-87 refuse typed while either is uncomposed).
    PortForwarding,
}

impl SelectionFeature {
    /// The stable token (shared by `--require` values, the requested
    /// feature list, and error messages).
    pub fn as_str(self) -> &'static str {
        match self {
            SelectionFeature::P2p => "p2p",
            SelectionFeature::Tor => "tor",
            SelectionFeature::SecureCore => "secure-core",
            SelectionFeature::Streaming => "streaming",
            SelectionFeature::Ipv6 => "ipv6",
            SelectionFeature::PortForwarding => "port-forwarding",
        }
    }
}

/// A required protocol as a selection constraint (§9.4's vocabulary;
/// FR-23P's protocol-compatibility stage). `smart` is deliberately
/// absent — smart-protocol resolution is the connection plane's (M4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SelectionProtocol {
    /// WireGuard over UDP.
    WireguardUdp,
    /// WireGuard over TCP.
    WireguardTcp,
    /// TLS-based Stealth.
    Stealth,
}

/// The §9.3 selection-plane modifiers a [`Request::Select`] carries.
/// Connection-plane modifiers (`--netshield`, `--kill-switch`,
/// `--nat`, `--vpn-accelerator`, `--dns`, `--lan-access`) are
/// deliberately NOT here: selection never composes them — the tunnel
/// does (FR-23E's composition boundary, recorded on
/// [`SelectionResult::feature_difference`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SelectionModifiers {
    /// The ranking policy (`official`|`balanced`|`load`|`latency`;
    /// `speed` and the other forbidden throughput signals are rejected
    /// typed by the daemon's parse).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// An explicit per-request physical country (FR-23Q's first
    /// source; uppercase ISO 3166-1 alpha-2 — non-canonical input
    /// refuses typed, never approximated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_country: Option<String>,
    /// Never select these countries (FR-21).
    pub excluded_countries: Vec<String>,
    /// Never select these states/regions (FR-21A).
    pub excluded_states: Vec<String>,
    /// Never select these cities (FR-21A).
    pub excluded_cities: Vec<String>,
    /// Never select these logical servers by name (FR-21A).
    pub excluded_servers: Vec<String>,
    /// Required features (T-4/FR-23H).
    pub required_features: Vec<SelectionFeature>,
    /// Optional features — never eliminate; feed the balanced
    /// feature-match term.
    pub optional_features: Vec<SelectionFeature>,
    /// Required protocol (FR-23P's protocol stage).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_protocol: Option<SelectionProtocol>,
}

/// Which FR-23Q source supplied the physical country.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PhysicalCountrySource {
    /// An explicit per-request value (`--physical-country`).
    ExplicitRequest,
    /// The configured `connection_groups.physical_country`.
    Config,
    /// The cached Proton user-location country (obtained through Muon
    /// while disconnected; read from the daemon's cache — this request
    /// performs no location fetch).
    CachedLocation,
}

/// The resolved physical country with its source (FR-23T carries both;
/// the country code is coarse location, not an IP — the redaction rules
/// for the fine-grained location payload do not apply to it, and
/// FR-23T explicitly requires the value on the selection surface).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PhysicalCountryValue {
    /// The uppercase ISO 3166-1 alpha-2 code.
    pub country: String,
    /// Which source supplied it.
    pub source: PhysicalCountrySource,
}

/// The catalog revisions a selection ran against (FR-23T's "catalog
/// revision" — disambiguated per the m3-plan U6 reading: the SERVER
/// catalog is the revision field's primary meaning; a group selection
/// additionally carries the group registry's own revision stamp).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SelectionCatalogProvenance {
    /// The cached server catalog revision's `ETag`, when one is cached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_catalog_etag: Option<String>,
    /// When the server catalog revision was fetched (Unix seconds);
    /// absent when no catalog is cached (a selection then refuses —
    /// never fabricates a revision).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_catalog_fetched_unix: Option<u64>,
    /// The connection-group registry's catalog revision stamp, present
    /// on group selections only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_catalog_revision: Option<String>,
}

/// A resolved group's identity and policy provenance (FR-23T's
/// `group_id`/`origin`; T-33's status-visible override).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GroupProvenance {
    /// The stable namespaced group id.
    pub group_id: String,
    /// The group's origin (`proton`|`protonwire`).
    pub origin: String,
    /// How the effective ranking policy was chosen
    /// (`catalog-default`|`declared-override`).
    pub policy_provenance: String,
}

/// The selector the request resolved to, after target grammar and
/// group-definition mapping (FR-23T's "resolved selector").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedSelector {
    /// The target kind token: `fastest`, `random`, `country`,
    /// `countries`, `state`, `city`, `server`, `gateway`, `p2p`,
    /// `tor`, `secure-core`, or `group`.
    pub target: String,
    /// The kind's parameter when it names one (the country code, the
    /// state/city/server/gateway name, the group id; the pinned
    /// entry/exit countries for `secure-core` render as `CH->SE`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The effective ranking policy token
    /// (`official`|`balanced`|`load`|`latency`|`random`).
    pub policy: String,
}

/// One hard-filter stage's accounting (FR-22's structured report, wire
/// form; stages with zero eliminations are omitted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StageReport {
    /// The stage's stable label (the selection core's evaluation-order
    /// vocabulary, e.g. `offline`, `target-geography`,
    /// `physical-country-exclusion`, `required-features`).
    pub stage: String,
    /// Candidates this stage eliminated.
    pub eliminated: usize,
}

/// FR-22's structured account of where every candidate went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HardFiltersReport {
    /// Candidates that entered the pipeline.
    pub considered: usize,
    /// Candidates still eligible after every stage.
    pub survivors: usize,
    /// The per-stage counts, in the evaluation order (nonzero stages
    /// only).
    pub stages: Vec<StageReport>,
}

/// The per-term decomposition of a balanced ranking (FR-16's formula,
/// wire form; lower is better).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WeightedBreakdownWire {
    /// `load_weight × normalized_load`.
    pub load_term: f32,
    /// `latency_weight × normalized_latency`.
    pub latency_term: f32,
    /// Zero until connection statistics exist (post-M4).
    pub stability_term: f32,
    /// `feature_weight × (1 − match_ratio)`.
    pub feature_match_term: f32,
    /// Zero until connection statistics exist (post-M4).
    pub history_term: f32,
    /// The weighted sum (lower is better).
    pub total: f32,
}

/// The scoring signals behind the winning candidate (FR-23T/FR-14:
/// status must identify the policy AND the signal provenance).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WinnerSignals {
    /// The signal provenance: `catalog-only` (Proton-exposed catalog
    /// fields alone), `probe-observed` (plus the bounded on-demand
    /// prober's latency), or `weighted-breakdown` (the balanced
    /// decomposition).
    pub provenance: String,
    /// The catalog's opaque Proton score, when exposed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proton_score: Option<f32>,
    /// The Proton-exposed load percentage, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<i8>,
    /// The latency observation, when one served the ranking
    /// (milliseconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// The balanced decomposition, when the balanced policy ranked the
    /// winner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weighted: Option<WeightedBreakdownWire>,
}

/// The winning server (FR-23T; FR-23D's both-ends rule for Secure Core
/// rides `entry_country`/`exit_country`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SelectedServer {
    /// The logical server ID.
    pub id: String,
    /// The display name (`UK#42`, `CH-SE#1`, ...).
    pub name: String,
    /// The route's entry country (equals the exit outside Secure
    /// Core).
    pub entry_country: String,
    /// The exit country — the canonical selector.
    pub exit_country: String,
    /// The city, when exposed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    /// The minimum plan tier (0 free .. 3 PM).
    pub tier: i8,
    /// The signals that ranked it.
    pub signals: WinnerSignals,
}

/// The full selection result — FR-23T's field set, end to end.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SelectionResult {
    /// The catalog revisions the selection ran against.
    pub catalog: SelectionCatalogProvenance,
    /// The group identity and policy provenance, on group selections
    /// only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<GroupProvenance>,
    /// The resolved selector (target + effective policy).
    pub selector: ResolvedSelector,
    /// The applied hard filters (FR-22's structured report).
    pub hard_filters: HardFiltersReport,
    /// The physical country that excluded exits, with its source —
    /// present only when the request's semantics used it (FR-23T's
    /// "when relevant").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_country: Option<PhysicalCountryValue>,
    /// The winning server.
    pub winner: SelectedServer,
    /// The selection-plane features the request carried (rendered
    /// tokens, required then optional).
    pub requested_features: Vec<String>,
    /// Requested-but-not-applied features. For REQUIRED features the
    /// difference is empty by construction — selection satisfies them
    /// (the winner carries them) or refuses. OPTIONAL features are
    /// prefer-not-require (they weight ranking, never eliminate), so
    /// the winner may legitimately lack one; the difference reports
    /// exactly those, through the core's one evaluation vocabulary.
    /// The connection-plane family (`netshield`, `nat`, `lan-access`,
    /// protocol-at-tunnel, the port-forwarding REQUEST) is composed by
    /// the M4 tunnel (FR-23E's boundary), and its differences land
    /// here from the connection transition, never from a query.
    pub feature_difference: Vec<String>,
}

/// A group's FR-23S availability evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GroupAvailability {
    /// Whether the group resolves to at least one eligible candidate
    /// over the current cached catalog.
    pub available: bool,
    /// The structured reason when unavailable: `no-catalog` (nothing
    /// cached yet), `physical-country-required` (FR-23Q),
    /// `entitlement-composition-missing` (a PF-requiring group with
    /// the entitlement seam uncomposed — none exist in the v1 catalog),
    /// or `no-eligible-server` (the FR-22 report eliminated
    /// everything).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One built-in group as the list surface serves it (FR-23U).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GroupSummary {
    /// The stable namespaced id (FR-23J).
    pub id: String,
    /// The display label.
    pub label: String,
    /// `proton` or `protonwire`.
    pub origin: String,
    /// The definition's verification source.
    pub definition_source: String,
    /// What entitlement the group needs.
    pub entitlement: String,
    /// The catalog-declared ranking policy token.
    pub ranking_policy: String,
    /// The request-time ranking overrides the catalog declares.
    pub allowed_ranking_overrides: Vec<String>,
    /// The FR-23S availability evaluation.
    pub availability: GroupAvailability,
}

/// The full built-in group catalog reply (FR-23I/U).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GroupsCatalog {
    /// The group registry's catalog revision stamp.
    pub catalog_revision: String,
    /// The regional taxonomy's revision identity.
    pub taxonomy_revision: String,
    /// Every built-in group, registry order.
    pub groups: Vec<GroupSummary>,
}

/// One group's full definition (`group show`; §7.3B's minimum
/// preserved representation, wire form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GroupDetails {
    /// The summary fields (id, label, origin, entitlement, policy,
    /// overrides, availability).
    pub summary: GroupSummary,
    /// Built-ins are immutable (FR-23M).
    pub immutable: bool,
    /// The connection type the target addresses, when the kind does
    /// not imply it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<String>,
    /// The target kind token (`fastest`, `fastest-in-country`,
    /// `fastest-in-region`, `random`, `secure-core`).
    pub target: String,
    /// The target's parameter when it names one (the country, the
    /// region; a Secure Core route renders `CH->SE`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_detail: Option<String>,
    /// The `protocol` override token, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_override: Option<String>,
    /// The remaining catalog-declared overrides, verbatim pairs
    /// (connection-time parameters — the M4 tunnel composes them).
    pub connection_overrides: Vec<[String; 2]>,
    /// The catalog's selection-authority annotation, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_authority: Option<String>,
    /// The definition's evidence sources.
    pub sources: Vec<String>,
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

    /// M3 U6: the selection surface rides the flat request shape —
    /// kebab-case method token, the target and modifiers beside the
    /// id; the feature and protocol vocabularies render kebab-case.
    #[test]
    fn u6_select_request_shape() {
        let json = serde_json::to_value(&Request::Select {
            target: ConnectTarget::Country {
                country: "GB".into(),
            },
            modifiers: SelectionModifiers {
                by: Some("balanced".into()),
                physical_country: Some("DE".into()),
                excluded_countries: vec!["US".into()],
                excluded_states: Vec::new(),
                excluded_cities: Vec::new(),
                excluded_servers: Vec::new(),
                required_features: vec![SelectionFeature::PortForwarding],
                optional_features: vec![SelectionFeature::P2p],
                required_protocol: Some(SelectionProtocol::WireguardUdp),
            },
        })
        .unwrap();
        assert_eq!(json["method"], "select");
        assert_eq!(json["params"]["target"]["kind"], "country");
        assert_eq!(json["params"]["modifiers"]["by"], "balanced");
        assert_eq!(json["params"]["modifiers"]["physical_country"], "DE");
        assert_eq!(
            json["params"]["modifiers"]["required_features"][0],
            "port-forwarding"
        );
        assert_eq!(json["params"]["modifiers"]["optional_features"][0], "p2p");
        assert_eq!(
            json["params"]["modifiers"]["required_protocol"],
            "wireguard-udp"
        );
        // Round-trips.
        let back: Request = serde_json::from_value(json).unwrap();
        assert!(matches!(back, Request::Select { .. }));

        // The unit-shaped group methods carry no params at all; the
        // show method carries its id.
        assert_eq!(
            serde_json::to_value(&Request::GroupsList).unwrap()["method"],
            "groups-list"
        );
        let show = serde_json::to_value(&Request::GroupShow {
            id: "proton:fastest-country".into(),
        })
        .unwrap();
        assert_eq!(show["method"], "group-show");
        assert_eq!(show["params"]["id"], "proton:fastest-country");
    }

    /// M3 U6 / FR-23T: the Selected result's wire shape — every
    /// FR-23T field present, absent optionals OFF the wire (a group
    /// selection carries the group provenance and the registry stamp;
    /// the feature difference is empty by the FR-23E boundary).
    #[test]
    fn u6_selected_result_carries_the_fr23t_field_set() {
        let result = SelectionResult {
            catalog: SelectionCatalogProvenance {
                server_catalog_etag: Some("\"rev-9\"".into()),
                server_catalog_fetched_unix: Some(1_771_000_000),
                group_catalog_revision: Some("groups-2026-08".into()),
            },
            group: Some(GroupProvenance {
                group_id: "protonwire:fastest-europe".into(),
                origin: "protonwire".into(),
                policy_provenance: "declared-override".into(),
            }),
            selector: ResolvedSelector {
                target: "countries".into(),
                detail: None,
                policy: "latency".into(),
            },
            hard_filters: HardFiltersReport {
                considered: 20,
                survivors: 1,
                stages: vec![
                    StageReport {
                        stage: "offline".into(),
                        eliminated: 3,
                    },
                    StageReport {
                        stage: "target-geography".into(),
                        eliminated: 16,
                    },
                ],
            },
            physical_country: Some(PhysicalCountryValue {
                country: "GB".into(),
                source: PhysicalCountrySource::ExplicitRequest,
            }),
            winner: SelectedServer {
                id: "id-CH#10".into(),
                name: "CH#10".into(),
                entry_country: "CH".into(),
                exit_country: "CH".into(),
                city: Some("Zurich".into()),
                tier: 2,
                signals: WinnerSignals {
                    provenance: "probe-observed".into(),
                    proton_score: Some(1.42),
                    load: Some(42),
                    latency_ms: Some(18),
                    weighted: None,
                },
            },
            requested_features: vec!["port-forwarding".into()],
            feature_difference: Vec::new(),
        };
        let json = serde_json::to_value(RequestResult::Selected {
            result: Box::new(result),
        })
        .unwrap();
        assert_eq!(json["result"], "selected");
        let data = &json["data"]["result"];
        assert_eq!(data["catalog"]["server_catalog_etag"], "\"rev-9\"");
        assert_eq!(data["catalog"]["group_catalog_revision"], "groups-2026-08");
        assert_eq!(data["group"]["group_id"], "protonwire:fastest-europe");
        assert_eq!(data["group"]["policy_provenance"], "declared-override");
        assert_eq!(data["selector"]["target"], "countries");
        assert_eq!(data["selector"]["policy"], "latency");
        assert!(data["selector"].get("detail").is_none());
        assert_eq!(data["hard_filters"]["considered"], 20);
        assert_eq!(data["hard_filters"]["survivors"], 1);
        assert_eq!(
            data["hard_filters"]["stages"][1]["stage"],
            "target-geography"
        );
        assert_eq!(data["hard_filters"]["stages"][1]["eliminated"], 16);
        assert_eq!(data["physical_country"]["country"], "GB");
        assert_eq!(data["physical_country"]["source"], "explicit-request");
        assert_eq!(data["winner"]["name"], "CH#10");
        assert_eq!(data["winner"]["signals"]["provenance"], "probe-observed");
        assert_eq!(data["winner"]["signals"]["latency_ms"], 18);
        assert!(data["winner"]["signals"].get("weighted").is_none());
        assert_eq!(data["requested_features"][0], "port-forwarding");
        assert_eq!(data["feature_difference"], serde_json::json!([]));
        // Round-trips.
        let back: RequestResult = serde_json::from_value(json).unwrap();
        assert!(matches!(back, RequestResult::Selected { .. }));

        // The no-group shape: group provenance and the registry stamp
        // stay OFF the wire entirely (never null-fabricated).
        let bare = SelectionResult {
            catalog: SelectionCatalogProvenance {
                server_catalog_etag: None,
                server_catalog_fetched_unix: None,
                group_catalog_revision: None,
            },
            group: None,
            physical_country: None,
            selector: ResolvedSelector {
                target: "fastest".into(),
                detail: None,
                policy: "official".into(),
            },
            hard_filters: HardFiltersReport {
                considered: 1,
                survivors: 1,
                stages: Vec::new(),
            },
            winner: SelectedServer {
                id: "id".into(),
                name: "GB#1".into(),
                entry_country: "GB".into(),
                exit_country: "GB".into(),
                city: None,
                tier: 0,
                signals: WinnerSignals {
                    provenance: "catalog-only".into(),
                    proton_score: None,
                    load: None,
                    latency_ms: None,
                    weighted: None,
                },
            },
            requested_features: Vec::new(),
            feature_difference: Vec::new(),
        };
        let json = serde_json::to_value(RequestResult::Selected {
            result: Box::new(bare),
        })
        .unwrap();
        let data = &json["data"]["result"];
        assert!(data.get("group").is_none());
        assert!(data.get("physical_country").is_none());
        assert!(data["catalog"].as_object().map(|o| o.is_empty()) == Some(true));
        assert!(data["winner"].get("city").is_none());
    }

    /// M3 U6 / FR-23S/U: the groups catalog and group-details wire
    /// shapes — availability reasons are structured tokens, the
    /// registry's revision stamps ride the catalog reply.
    #[test]
    fn u6_groups_wire_shapes() {
        let catalog = GroupsCatalog {
            catalog_revision: "rev-a".into(),
            taxonomy_revision: "un-m49@2026".into(),
            groups: vec![GroupSummary {
                id: "proton:fastest-country".into(),
                label: "Fastest country".into(),
                origin: "proton".into(),
                definition_source: "proton-api".into(),
                entitlement: "plan-dependent".into(),
                ranking_policy: "proton-score".into(),
                allowed_ranking_overrides: Vec::new(),
                availability: GroupAvailability {
                    available: true,
                    reason: None,
                },
            }],
        };
        let json = serde_json::to_value(RequestResult::Groups { catalog }).unwrap();
        assert_eq!(json["result"], "groups");
        let data = &json["data"]["catalog"];
        assert_eq!(data["catalog_revision"], "rev-a");
        assert_eq!(data["taxonomy_revision"], "un-m49@2026");
        let group = &data["groups"][0];
        assert_eq!(group["id"], "proton:fastest-country");
        assert_eq!(group["origin"], "proton");
        assert_eq!(group["ranking_policy"], "proton-score");
        assert_eq!(group["availability"]["available"], true);
        assert!(group["availability"].get("reason").is_none());
        let back: RequestResult = serde_json::from_value(json).unwrap();
        assert!(matches!(back, RequestResult::Groups { .. }));

        // An unavailable group carries its structured reason.
        let unavailable = GroupAvailability {
            available: false,
            reason: Some("physical-country-required".into()),
        };
        let json = serde_json::to_value(unavailable).unwrap();
        assert_eq!(json["reason"], "physical-country-required");

        // The details shape: the verbatim override pairs and the
        // evidence sources ride `group show`.
        let details = GroupDetails {
            summary: GroupSummary {
                id: "proton:gaming".into(),
                label: "Gaming".into(),
                origin: "proton".into(),
                definition_source: "official-client-compat".into(),
                entitlement: "target-and-feature-dependent".into(),
                ranking_policy: "proton-score".into(),
                allowed_ranking_overrides: Vec::new(),
                availability: GroupAvailability {
                    available: true,
                    reason: None,
                },
            },
            immutable: true,
            connection_type: Some("standard".into()),
            target: "fastest".into(),
            target_detail: None,
            protocol_override: None,
            connection_overrides: vec![["nat".into(), "moderate".into()]],
            selection_authority: None,
            sources: vec!["android-initial-profiles".into()],
        };
        let json = serde_json::to_value(RequestResult::Group {
            group: Box::new(details),
        })
        .unwrap();
        assert_eq!(json["result"], "group");
        let data = &json["data"]["group"];
        assert_eq!(data["summary"]["id"], "proton:gaming");
        assert_eq!(data["immutable"], true);
        assert_eq!(data["connection_type"], "standard");
        assert_eq!(data["target"], "fastest");
        assert_eq!(data["connection_overrides"][0][0], "nat");
        assert_eq!(data["connection_overrides"][0][1], "moderate");
        assert_eq!(data["sources"][0], "android-initial-profiles");
        assert!(data.get("protocol_override").is_none());
        let back: RequestResult = serde_json::from_value(json).unwrap();
        assert!(matches!(back, RequestResult::Group { .. }));
    }
}
