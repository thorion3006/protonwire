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

/// Preferred policy-routing table IDs (PRD 7.5); dynamically reallocated on
/// conflict by the Milestone 5 router (integration test IT-25).
pub mod route_tables {
    /// First preferred table.
    pub const PRIMARY: u32 = 51820;
    /// Second preferred table.
    pub const SECONDARY: u32 = 51821;
    /// Third preferred table.
    pub const TERTIARY: u32 = 51822;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_adapter_reports_native() {
        assert_eq!(NativeAdapter.kind(), NetworkIntegration::Native);
    }

    #[test]
    fn preferred_route_tables_match_prd() {
        assert_eq!(route_tables::PRIMARY, 51820);
        assert_eq!(route_tables::SECONDARY, 51821);
        assert_eq!(route_tables::TERTIARY, 51822);
    }
}
