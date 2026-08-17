//! Privacy policy: routing, split tunneling, kill switch (Milestones 5/7).
//!
//! This crate owns the *rules*: which routes exist, which traffic the kill
//! switch blocks, which traffic bypasses the tunnel. `protonwire-net`
//! renders them onto the host. The nftables implementation crate
//! (recommended: `rustables` for transactional batch semantics without a C
//! dependency; fallback: mullvad `nftnl-rs`) lands with Milestone 5 per
//! `docs/spike-2026-08.md`.

/// One rendered policy rule, before it is applied to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRule {
    /// Route a destination through the tunnel.
    RouteThroughTunnel {
        /// Destination CIDR.
        cidr: String,
    },
    /// Exclude a destination from the tunnel (split tunnel bypass).
    Bypass {
        /// Destination CIDR or symbolic selector.
        selector: String,
    },
    /// Block traffic that would leave without the tunnel (kill switch).
    BlockUncovered {
        /// Rule priority for ordering with third-party rules.
        priority: i32,
    },
}

/// Kill-switch ownership marker written into every object this crate
/// generates, so cleanup is idempotent and never touches unowned state.
pub const OWNERSHIP_TAG: &str = "protonwire";

/// Kill-switch generation identifier; atomic replaces bump the generation
/// rather than merging rules (PRD 7.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GenerationId(pub u64);

/// Errors from policy rendering.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The requested rule set is internally inconsistent.
    #[error("inconsistent policy: {0}")]
    Inconsistent(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_carry_distinct_intents() {
        let a = PolicyRule::RouteThroughTunnel {
            cidr: "0.0.0.0/0".into(),
        };
        let b = PolicyRule::Bypass {
            selector: "10.0.0.0/8".into(),
        };
        let c = PolicyRule::BlockUncovered { priority: -100 };
        assert_ne!(a, b);
        assert_ne!(b, c);
    }
}
