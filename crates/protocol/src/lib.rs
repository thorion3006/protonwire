//! ProTUN adapter — the required tunnel engine (PRD 6.5).
//!
//! All ProTUN-specific types stay behind this crate so an upstream beta API
//! change is localized (PRD 6.5 rule 8). The pinned crate is re-exported so
//! the workspace lockfile governs resolution. The adapter arrives in
//! Milestone 4:
//!
//! * TUN creation (`protonwire0`) and owned-FD hand-off to
//!   `Connection::unix_connect`
//! * peer/port candidate translation for UDP, TCP (WireGuard), and TLS
//!   (Stealth) endpoints
//! * LocalAgent production mode with certificate refresh and feature
//!   reconciliation
//! * the encrypted three-value persistent cache facade
//! * outer-socket marks before route commit, statistics, bounded capture,
//!   and disconnect cleanup

pub mod params;
pub mod translate;

pub use params::{PeerParams, TunnelParams};
pub use translate::translate;

pub use protun;

/// The tunnel surface core programs against (Milestone 4).
pub trait TunnelEngine: Send + Sync {
    /// Engine identity for status reporting.
    fn engine_name(&self) -> &'static str {
        "protun"
    }
}

/// Tunnel integration address contract (PRD FR-27, OQ-15).
///
/// ProTUN v2.2.1 does not negotiate Linux TUN addresses through its public
/// API. These values reproduce the integration addresses the pinned
/// `pvpnclient` 3.0.3 source configures, and Milestone 4's adapter
/// conformance test asserts the live adapter still configures exactly these
/// values. If ProTUN ever exposes negotiated addresses, this contract is
/// retired in favor of the public API.
pub mod tun_contract {
    /// TUN interface IPv4 address.
    pub const IPV4_ADDRESS: &str = "10.2.0.2/32";
    /// TUN interface IPv4 gateway (internal ProTUN peer address).
    pub const IPV4_GATEWAY: &str = "10.2.0.1";
    /// TUN interface IPv6 address.
    pub const IPV6_ADDRESS: &str = "2a07:b944::2:2/128";
    /// TUN interface IPv6 gateway.
    pub const IPV6_GATEWAY: &str = "2a07:b944::2:1";
}

/// Protocol capability reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    /// Smart Protocol (ProTUN-chosen) — the default: an
    /// unconfigured request lets the engine choose.
    #[default]
    /// Smart Protocol (ProTUN-chosen).
    Smart,
    /// WireGuard over UDP.
    WireGuardUdp,
    /// WireGuard over TCP.
    WireGuardTcp,
    /// Stealth (TLS).
    Stealth,
}

/// Errors from the tunnel adapter.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// The requested protocol is unavailable in the current adapter.
    #[error("protocol unavailable: {0:?}")]
    Unavailable(Protocol),
    /// The engine failed.
    #[error("tunnel failure: {0}")]
    Tunnel(String),
    /// FR-27: the connection shape needs a client key the caller did
    /// not supply (the persistent-cache lane, PR-2, makes it optional
    /// later — the translation refuses the un-wired shape typed).
    #[error("missing client key: {0}")]
    MissingKey(String),
    /// A malformed key — never trimmed, padded, or retried.
    #[error("invalid client key: {0}")]
    InvalidKey(String),
    /// A malformed peer field; the peer is skipped among healthy
    /// ones, refused when none remain.
    #[error("invalid peer `{0}`: {1}")]
    InvalidPeer(String, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tunnel address contract is pvpnclient-derived (OQ-15):
    /// the M4 PR-3 conformance test asserts the LIVE adapter
    /// configures exactly these values; here we pin the FORMAT
    /// (address/prefix split, parseable v4 and v6) so a typo in the
    /// constants cannot ride to that test.
    #[test]
    fn tun_contract_addresses_are_well_formed() {
        let (address, prefix) = tun_contract::IPV4_ADDRESS
            .split_once('/')
            .unwrap_or_else(|| panic!("no prefix: {}", tun_contract::IPV4_ADDRESS));
        assert_eq!(prefix, "32", "the /32 host route");
        address
            .parse::<std::net::Ipv4Addr>()
            .expect("the v4 address parses");
        tun_contract::IPV4_GATEWAY
            .parse::<std::net::Ipv4Addr>()
            .expect("the v4 gateway parses");
        let (address, prefix) = tun_contract::IPV6_ADDRESS
            .split_once('/')
            .unwrap_or_else(|| panic!("no prefix: {}", tun_contract::IPV6_ADDRESS));
        assert_eq!(prefix, "128", "the /128 host route");
        address
            .parse::<std::net::Ipv6Addr>()
            .expect("the v6 address parses");
        tun_contract::IPV6_GATEWAY
            .parse::<std::net::Ipv6Addr>()
            .expect("the v6 gateway parses");
    }
}
