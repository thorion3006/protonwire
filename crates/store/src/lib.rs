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

pub mod config;
pub mod paths;
pub mod state;
pub mod yaml;

pub use config::{
    Authority, DnsMode, KillSwitchMode, LanPolicy, NatMode, NetShieldLevel, OutputFormat,
    SystemConfig, UserOverlay,
};
pub use paths::ConfigPaths;
pub use state::{StateFile, StateStore};
pub use yaml::{YamlError, from_slice, from_str};
