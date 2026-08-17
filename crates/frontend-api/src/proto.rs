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
    Request {
        /// Client-side correlation id, echoed in the response.
        id: u64,
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

    #[test]
    fn request_wire_shape_is_stable() {
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
                    "request": { "method": "ping", "params": { "nonce": "abc" } }
                }
            })
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
