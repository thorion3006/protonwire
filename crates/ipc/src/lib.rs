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

pub use authz::{authorize, required_role, IpcRole};
pub use bus::EventBus;
pub use client::{ConnectError, IpcClient, SecurityChecks};
pub use peer::PeerCredentials;
pub use server::{RequestHandler, SessionContext};
