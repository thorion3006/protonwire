//! ProtonWire core: the sole implementation of product behavior
//! (PRD FR-127C, ADR-0001).
//!
//! The daemon is a thin privileged host around this crate. Core owns the
//! connection state machine, request dispatch, event sequencing, and the
//! redaction machinery every other component reuses. Infrastructure (Muon
//! API, ProTUN tunnel, netlink, storage) reaches core through traits; core
//! never depends on a client, a presentation framework, or a transport.

pub mod error;
pub mod redact;
pub mod state;

pub use error::CoreError;
pub use redact::{init_tracing, scrub, RedactingMakeWriter, SecretString};
pub use state::{DaemonCore, EventSink, EventSinkFn};
