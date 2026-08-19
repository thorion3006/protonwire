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
}

/// Successful request outcomes.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "result", content = "data", rename_all = "kebab-case")]
pub enum RequestResult {
    /// Reply to [`Request::Ping`].
    Pong { nonce: String },
    /// Reply to [`Request::GetState`].
    State { state: DaemonState },
    /// Reply to [`Request::Disconnect`] / [`Request::Shutdown`].
    Acknowledged,
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
    pub fn from_error(error: &RpcError) -> Option<Self> {
        serde_json::from_value(error.details.clone()?).ok()
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
}
