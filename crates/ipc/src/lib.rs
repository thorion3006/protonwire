//! Unix-domain-socket IPC transport for the ProtonWire frontend API
//! (PRD 6.3, FR-127).
//!
//! The daemon side ([`server::IpcServer`]) binds a root-owned socket,
//! authenticates peers with `SO_PEERCRED`, enforces per-method role
//! requirements, and fans events out to connected clients. The client side
//! ([`client::IpcClient`]) performs the hello handshake, verifies socket
//! ownership, and correlates requests with responses while queuing events.
//!
//! The transport is deliberately synchronous (thread-per-session): IPC peers
//! are few and local, and this keeps the daemon's future async core (ProTUN,
//! Milestone 4) decoupled from frontend I/O via channels.

pub mod authz;
pub mod bus;
pub mod client;
pub mod frame;
pub mod peer;
pub mod server;

/// In-process test fixture; compiled for this crate's own tests and for
/// downstream test builds that enable the `test-util` feature. Never part
/// of a release build.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use authz::{IpcRole, authorize, required_role};
pub use bus::EventBus;
pub use client::{ConnectError, IpcClient, SecurityChecks};
pub use peer::PeerCredentials;
pub use server::{RequestHandler, SessionContext};
