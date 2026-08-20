//! Persistence layer: configuration, daemon state, cache locations.
//!
//! Loading rules (PRD section 10):
//!
//! * YAML input is size-capped and parsed by [`serde_norway`] behind the
//!   guard in [`yaml`], which also rejects duplicate keys.
//! * Typed documents use `deny_unknown_fields` so unknown or misspelled
//!   keys are hard errors, never silently ignored.
//! * Every configuration field carries an authority class; per-UID overlays
//!   are a distinct document from the system configuration and can never
//!   express system-only fields.

pub mod catalog;
pub mod config;
pub mod credential_input;
pub mod deadlines;
pub mod fs_trust;
pub mod paths;
pub mod session;
pub mod state;
pub mod writable_store;
pub mod yaml;

pub use config::{
    Authority, ConnectionType, CredentialInputSource, DnsLeakProtection, DnsMode, DnsPolicy,
    Ipv6Mode, KillSwitchMode, LanPolicy, NatMode, NetShieldLevel, OutputFormat, ProbeTransport,
    ProfileRanking, ProtocolMode, RegionalRanking, SplitRuleAction, SystemConfig, UserOverlay,
    WritableSessionStore,
};
pub use paths::ConfigPaths;
pub use state::{StateFile, StateStore};
pub use yaml::{YamlError, from_slice, from_str};
