//! Versioned frontend API schema for ProtonWire (PRD 7.16, NFR-40).
//!
//! This crate is the single source of truth for every type that crosses the
//! daemon ↔ client Unix-socket boundary. All three first-party clients
//! (CLI, TUI, GUI) and the shared client SDK consume these types; the daemon
//! produces them. JSON Schemas are generated from these types by
//! `cargo xtask schema-gen` and committed under `schemas/frontend/`.
//!
//! Wire compatibility rules:
//!
//! * Every message carries the protocol version during the hello handshake.
//! * Additive changes (new enum variants, new optional fields) bump the minor
//!   protocol version; incompatible changes require a new major version and a
//!   parallel server implementation during migration.
//! * Events carry a monotonic sequence number; a client that observes a gap
//!   must perform a full-state resynchronization via [`Request::GetState`].

pub mod event;
pub mod proto;
pub mod schema;
pub mod state;

pub use event::{
    CatalogRefreshResult, EVENT_SEQ_RESYNC_NOW, Event, EventEnvelope, NoticeLevel,
    RESYNC_MARKER_INTRODUCED_IN, resync_marker_reaches,
};
pub use proto::{
    ClientInfo, ClientMessage, ClientSurface, ConfirmationRequirement, ConnectTarget, HelloAck,
    HelloError, PROTOCOL_VERSION, Request, RequestResult, Response, RpcError, RpcErrorCode,
    ServerMessage, SpecialClass,
};
pub use state::{DaemonState, NetworkIntegration, VpnState};
