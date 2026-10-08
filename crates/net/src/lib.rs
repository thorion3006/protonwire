//! Linux network control and integration adapters (PRD 6.6, Milestone 5).
//!
//! ProtonWire owns the TUN interface and all privacy policy in every mode;
//! the integration mode only controls uplink observation and DNS
//! cooperation. Every adapter implements [`NetworkAdapter`] with identical
//! guarantees:
//!
//! * discover default-route interfaces, gateways, DNS domains, connectivity
//! * notify the daemon of link/address/route/network-switch events
//! * install and remove only ProtonWire-owned state, idempotently
//! * survive manager restarts without a leak window
//! * never touch the user's uplink profiles or `.network` files
//!
//! The netlink route crate (recommended: `rtnetlink`/`netlink-packet-route`,
//! fallback: a hand-rolled `netlink-sys` request loop) lands with Milestone
//! 5 per `docs/spike-2026-08.md`.

use protonwire_frontend_api::NetworkIntegration;

/// The uplink/network-manager surface core programs against.
pub trait NetworkAdapter: Send + Sync {
    /// Adapter identity, as exposed in status.
    fn kind(&self) -> NetworkIntegration;

    /// Human-readable description for diagnostics.
    fn describe(&self) -> &'static str;
}

/// Direct netlink observation; the default when no manager owns the uplink.
pub struct NativeAdapter;

impl NetworkAdapter for NativeAdapter {
    fn kind(&self) -> NetworkIntegration {
        NetworkIntegration::Native
    }

    fn describe(&self) -> &'static str {
        "native netlink observation (Milestone 5)"
    }
}

/// The routing-table plan (FR-34, IT-25): preferred-not-guaranteed
/// ids, persisted-mapping ownership proof, conflict-free allocation,
/// lookalike refusal. The M1 `route_tables` id-constants placeholder
/// grew into this.
pub mod tables;

/// The transactional netlink writer (FR-33/38): batched route/rule
/// operations with rollback of the applied prefix, every op gated by
/// the table plan (IT-25's lookalike refusal wired into the writer).
pub mod route_txn;

/// The routing desired-state lifecycle (FR-35/39/40): the
/// full-tunnel desired ops, the drift repair diff, and the
/// owned-state cleanup enumeration.
pub mod route_drift;

/// DNS management (FR-41..49B): mode detection, per-backend
/// application (systemd-resolved or /etc/resolv.conf), strict
/// leak-proof validation, revert on disconnect.
pub mod dns;

/// Integration adapters (PRD 6.6, IT-16/17/20): observation and
/// cooperation with NetworkManager and systemd-networkd;
/// IT-20 conflict events.
pub mod adapters;

/// The session orchestrator (M5 slice 8): the connect and disconnect
/// sequences composing kill switch + routes + DNS.
pub mod session;

/// The nftables kill switch (FR-56..65): an atomically replaced inet
/// table whose output chain defaults to DROP, ownership by marker
/// chain + persisted generation, lookalike refusal, fail-closed
/// validation.
pub mod kill_switch;

/// The network-namespace integration-test harness (NFR-31). Shared by
/// every netns-gated integration test in the workspace (`protocol`'s
/// IT-1 today, this crate's M5 suite next); the runner is
/// `cargo xtask netns-it`.
pub mod netns;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_adapter_reports_native() {
        assert_eq!(NativeAdapter.kind(), NetworkIntegration::Native);
    }
}
