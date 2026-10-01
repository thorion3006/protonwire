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
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::Protocol;

/// One transport's endpoint: the entry address and its port
/// candidates — the catalog's own `ProtocolEndpoint` shape (an
/// address-and-ports PAIR per transport: the addresses may DIFFER
/// across transports on one physical, which a single flattened
/// address cannot express — the bot round-2 P1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportEndpoint {
    /// The entry address for THIS transport.
    pub entry_ip: IpAddr,
    /// Port candidates, priority order.
    pub ports: Vec<u16>,
}

/// One connection candidate physical: the network identity ProTUN
/// cycles through, composed by the caller from the catalog's
/// `PhysicalServer` (the daemon join: selection's logical winner →
/// its online physicals, priority order preserved).
#[derive(Clone, PartialEq)]
pub struct PeerParams {
    /// The caller's stable id for the peer (rides ProTUN's state
    /// events back — `peer_id`).
    pub id: String,
    /// The server's WireGuard X25519 public key (base64).
    pub public_key_base64: String,
    /// The UDP endpoint; `None` when the transport is not served.
    pub udp: Option<TransportEndpoint>,
    /// The TCP endpoint; `None` when not served.
    pub tcp: Option<TransportEndpoint>,
    /// The TLS (Stealth) endpoint; `None` when not served.
    pub tls: Option<TransportEndpoint>,
    /// Lower connects first (the caller's ranking; selection's
    /// official order is the precedent).
    pub priority: i32,
    /// The exit location label (status rendering; the catalog's
    /// `Domain` or the logical's country, per the caller).
    pub exit_label: Option<String>,
}

/// SEC-5/FR-121: full entry addresses never render. A derived Debug
/// would print every transport's `entry_ip` verbatim into the exact
/// downstream `debug!("{params:?}")` scenario TunnelParams' manual
/// Debug exists to make safe — the manual impl redacts them (the
/// core redact.rs precedent; ports, keys, and labels are catalog
/// data, not addresses).
impl std::fmt::Debug for PeerParams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let endpoint = |transport: &str, endpoint: &Option<TransportEndpoint>| {
            endpoint.as_ref().map(|endpoint| {
                format!("{transport}={{ip=[redacted], ports={:?}}}", endpoint.ports)
            })
        };
        formatter
            .debug_struct("PeerParams")
            .field("id", &self.id)
            .field("public_key_base64", &self.public_key_base64)
            .field("udp", &endpoint("udp", &self.udp))
            .field("tcp", &endpoint("tcp", &self.tcp))
            .field("tls", &endpoint("tls", &self.tls))
            .field("priority", &self.priority)
            .field("exit_label", &self.exit_label)
            .finish()
    }
}

/// The client's private WireGuard key (base64) in ZEROIZING storage
/// (NFR-16A; the core's `SecretString` precedent — this crate cannot
/// depend on core, so the same shape lives here): the allocation
/// zeroizes when the last handle drops, clones SHARE it (no
/// unzeroized duplication), and Debug never renders it. The pinned
/// upstream API ultimately accepts ordinary bytes — NFR-16A's own
/// text records that as best effort; the lifecycle boundaries
/// (never in Debug, never in errors, zeroizing at this layer) are
/// what the tests pin.
#[derive(Clone)]
pub struct ClientPrivateKey(Arc<Zeroizing<String>>);

impl ClientPrivateKey {
    /// Wraps the base64 key material. The caller's allocation moves
    /// into zeroizing storage directly — no intermediate copy.
    pub fn new(base64_key: String) -> Self {
        Self(Arc::new(Zeroizing::new(base64_key)))
    }

    /// Read access for the deliberate consumer (translate's decode —
    /// the only reader).
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ClientPrivateKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClientPrivateKey([redacted])")
    }
}

/// The TLS SNI strategy (FR-27's configured-strategy requirement):
/// engine-agnostic so `connection.protun.sni_strategy` can ride
/// TunnelParams (the daemon lane maps the config string through
/// [`Self::parse`]; translate maps this onto ProTUN's enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SniStrategy {
    /// A random SNI per connection (the default).
    #[default]
    Random,
    /// The top-of-catalog SNI.
    Top,
}

impl SniStrategy {
    /// Parses the config vocabulary (`connection.protun.sni_strategy`,
    /// validated to exactly these spellings store-side).
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "random" => Some(Self::Random),
            "top" => Some(Self::Top),
            _ => None,
        }
    }
}

/// The full connection request in ProtonWire's vocabulary (FR-27):
/// peers, mode, and the session facts the engine needs. Composed by
/// the daemon lane (PR-5); consumed ONLY through crate::translate.
#[derive(Clone, Default)]
pub struct TunnelParams {
    /// The candidate peers, priority order (ProTUN cycles them per
    /// its own reachability logic — the ORDER is the caller's only
    /// steering).
    pub peers: Vec<PeerParams>,
    /// The requested protocol (Smart lets ProTUN choose; a MANUAL
    /// request constrains every translated peer to that transport —
    /// FR-32G/ER-11, never a silent protocol change).
    pub protocol: Protocol,
    /// Whether the OS reports network connectivity right now
    /// (ProTUN's `network_available`).
    pub network_available: bool,
    /// The client's private WireGuard key — the connection's
    /// identity, in zeroizing storage. `None` only in LocalAgent
    /// mode, where ProTUN reads (or generates and persists) it
    /// through the cache (PR-2's lane; `translate` refuses the
    /// mismatched shapes typed).
    pub client_private_key: Option<ClientPrivateKey>,
    /// The configured SNI strategy (FR-27: the system config reaches
    /// the engine — pre-fix translation hard-coded Random).
    pub sni_strategy: SniStrategy,
}

/// FR-7P/T-32 discipline: the private key never renders. A derived
/// Debug on TunnelParams would print the key verbatim into any
/// downstream `debug!("{params:?}")`; the manual impl scrubs it.
impl std::fmt::Debug for TunnelParams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TunnelParams")
            .field("peers", &self.peers)
            .field("protocol", &self.protocol)
            .field("network_available", &self.network_available)
            .field("client_private_key", &self.client_private_key)
            .field("sni_strategy", &self.sni_strategy)
            .finish()
    }
}

impl TunnelParams {
    /// Whether any peer can serve the requested protocol at all —
    /// the honest pre-flight for a typed refusal before the engine
    /// spins up (an endpoint without ports is a dead connection
    /// cycle).
    pub fn serves_requested_protocol(&self) -> bool {
        let serves = |peer: &PeerParams| match self.protocol {
            Protocol::Smart => {
                peer.udp.as_ref().is_some_and(|e| !e.ports.is_empty())
                    || peer.tcp.as_ref().is_some_and(|e| !e.ports.is_empty())
                    || peer.tls.as_ref().is_some_and(|e| !e.ports.is_empty())
            }
            Protocol::WireGuardUdp => peer.udp.as_ref().is_some_and(|e| !e.ports.is_empty()),
            Protocol::WireGuardTcp => peer.tcp.as_ref().is_some_and(|e| !e.ports.is_empty()),
            Protocol::Stealth => peer.tls.as_ref().is_some_and(|e| !e.ports.is_empty()),
        };
        self.peers.iter().any(serves)
    }
}
