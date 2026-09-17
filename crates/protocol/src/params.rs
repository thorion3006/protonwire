//! FR-27's translation layer: everything a connection needs, in
//! ProtonWire's own vocabulary, mapped onto ProTUN's config types.
//!
//! The boundary rule (PRD 6.5): ProTUN types never leak past this
//! crate. [`TunnelParams`] is the engine-agnostic shape the daemon
//! composes (selection winner -> physical -> peers); crate::translate
//! turns it into ProTUN's InitialConnectionConfig — the ONLY place
//! the mapping lives, so an upstream beta change is a one-file edit
//! (M4 PR-1).

use std::net::IpAddr;

use crate::Protocol;

/// One connection candidate physical: the network identity ProTUN
/// cycles through, composed by the caller from the catalog's
/// `PhysicalServer` (the daemon join: selection's logical winner →
/// its online physicals, priority order preserved).
#[derive(Debug, Clone, PartialEq)]
pub struct PeerParams {
    /// The caller's stable id for this peer (rides ProTUN's state
    /// events back — `peer_id`).
    pub id: String,
    /// The entry address to reach (per-protocol IPv4 preferred; the
    /// legacy `EntryIP` shape maps per the catalog contract).
    pub entry_ip: IpAddr,
    /// The server's WireGuard X25519 public key (base64).
    pub public_key_base64: String,
    /// UDP port candidates, priority order (empty: UDP not served).
    pub udp_ports: Vec<u16>,
    /// TCP port candidates, priority order (empty: TCP not served).
    pub tcp_ports: Vec<u16>,
    /// TLS port candidates, priority order (empty: Stealth not served).
    pub tls_ports: Vec<u16>,
    /// Lower connects first (the caller's ranking; selection's
    /// official order is the precedent).
    pub priority: i32,
    /// The exit location label (status rendering; the catalog's
    /// `Domain` or the logical's country, per the caller).
    pub exit_label: Option<String>,
}

/// The full connection request in ProtonWire's vocabulary (FR-27):
/// peers, mode, and the session facts the engine needs. Composed by
/// the daemon lane (PR-5); consumed ONLY through crate::translate.
#[derive(Clone)]
pub struct TunnelParams {
    /// The candidate peers, priority order (ProTUN cycles them per
    /// its own reachability logic — the ORDER is the caller's only
    /// steering).
    pub peers: Vec<PeerParams>,
    /// The requested protocol (Smart lets ProTUN choose).
    pub protocol: Protocol,
    /// Whether the OS reports network connectivity right now
    /// (ProTUN's `network_available`).
    pub network_available: bool,
    /// The client's private WireGuard key, base64 — the connection's
    /// identity. `None` only in LocalAgent mode, where ProTUN reads
    /// (or generates and persists) it through the cache (PR-2's
    /// lane; `translate` refuses the mismatched shapes typed).
    pub client_private_key_base64: Option<String>,
}

/// FR-7P/T-32 discipline: the private key never renders. A derived
/// Debug on TunnelParams would print `client_private_key_base64`
/// verbatim into any downstream `debug!("{params:?}")`; the manual
/// impl scrubs it (the core's `redact.rs` SecretString precedent).
impl std::fmt::Debug for TunnelParams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TunnelParams")
            .field("peers", &self.peers)
            .field("protocol", &self.protocol)
            .field("network_available", &self.network_available)
            .field("client_private_key_base64", &"[redacted]")
            .finish()
    }
}

impl TunnelParams {
    /// Whether any peer can serve the requested protocol at all —
    /// the honest pre-flight for a typed refusal before the engine
    /// spins up (an empty port set for the requested transport is a
    /// dead connection cycle).
    pub fn serves_requested_protocol(&self) -> bool {
        match self.protocol {
            Protocol::Smart => self.peers.iter().any(|peer| {
                !peer.udp_ports.is_empty()
                    || !peer.tcp_ports.is_empty()
                    || !peer.tls_ports.is_empty()
            }),
            Protocol::WireGuardUdp => self.peers.iter().any(|p| !p.udp_ports.is_empty()),
            Protocol::WireGuardTcp => self.peers.iter().any(|p| !p.tcp_ports.is_empty()),
            Protocol::Stealth => self.peers.iter().any(|p| !p.tls_ports.is_empty()),
        }
    }
}
