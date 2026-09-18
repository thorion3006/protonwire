//! The mapping [`TunnelParams`] → ProTUN's
//! [`InitialConnectionConfig`] — the one place the translation lives
//! (PRD 6.5's localization rule). Pure: no I/O, no clock, no
//! allocation beyond the output; the same params always translate to
//! the same config.

use protun::api::connection::{
    ConnectionMode, InitialConnectionConfig, IpAddress, PeerInfo, WgClientPrivateKey,
    WgPeerPublicKey,
};

use zeroize::Zeroizing;

use crate::ProtocolError;
use crate::params::TunnelParams;

/// Translates the connection request into ProTUN's config shape.
///
/// # Errors
/// * [`ProtocolError::MissingKey`] — `NoLocalAgent` mode (a
///   non-Smart... any protocol) without a client private key: ProTUN
///   would read one from the persistent cache, which PR-2 wires; the
///   translation refuses the un-wired shape typed rather than
///   letting the engine block on a cache that does not exist yet.
/// * [`ProtocolError::InvalidKey`] — a malformed (non-base64, wrong
///   length) key: never trimmed, padded, or retried.
/// * [`ProtocolError::InvalidPeer`] — a malformed peer key or entry
///   address: the peer is skipped ONLY when another well-formed peer
///   exists; a field error on the LAST well-formed peer refuses.
/// * [`ProtocolError::Unavailable`] — the successfully decoded peer
///   set cannot serve the requested transport (the post-skip
///   recheck: the pre-flight may have passed on a peer that
///   decoding then dropped).
pub fn translate(params: &TunnelParams) -> Result<InitialConnectionConfig, ProtocolError> {
    // The dead-transport pre-flight AT the choke point (the gate
    // review's catch): every candidate lacking the requested
    // transport's ports is a connection cycle that cannot answer —
    // refuse typed here, not only at the daemon's pre-flight call.
    // An EMPTY peer set is a different bug class (the caller never
    // composed peers) and keeps its own typed refusal below.
    if !params.peers.is_empty() && !params.serves_requested_protocol() {
        return Err(ProtocolError::Unavailable(params.protocol));
    }
    let peers = translate_peers(&params.peers)?;
    // The POST-SKIP recheck (the bot round's P2): the pre-flight
    // passed over the RAW set — a malformed peer may have been the
    // only one carrying the requested transport's ports, and its
    // skip above left a set that cannot serve the request. The
    // recheck runs over the DECODED survivors.
    if !serves_translated(&peers, params.protocol) {
        return Err(ProtocolError::Unavailable(params.protocol));
    }
    let peers = constrain_transports(peers, params.protocol)?;
    let wg_private_key = match &params.client_private_key {
        Some(key) => Some(decode_client_key(key.expose())?),
        None => None,
    };
    // The connection mode is the SAME for every protocol in this
    // milestone: no LocalAgent session engine exists yet (the M4
    // PR-4 lane wires `ConnectionMode::LocalAgent`).
    let connection_mode = match wg_private_key {
        Some(key) => ConnectionMode::NoLocalAgent {
            wg_private_key: Some(key),
        },
        None => {
            return Err(ProtocolError::MissingKey(
                "the client private key is required until the LocalAgent lane wires the \
                 persistent cache (PR-2/PR-4)"
                    .to_owned(),
            ));
        }
    };
    let sni_strategy = match params.sni_strategy {
        crate::params::SniStrategy::Random => protun::api::connection::SniStrategy::Random,
        crate::params::SniStrategy::Top => protun::api::connection::SniStrategy::Top,
    };
    Ok(InitialConnectionConfig {
        peers,
        network_available: params.network_available,
        pcap_file: None,
        connection_mode,
        sni_strategy,
    })
}

/// Whether the decoded peer set serves the requested transport.
fn serves_translated(peers: &[PeerInfo], protocol: crate::Protocol) -> bool {
    let serves = |peer: &PeerInfo| match protocol {
        crate::Protocol::Smart => {
            !peer.udp_ports.is_empty() || !peer.tcp_ports.is_empty() || !peer.tls_ports.is_empty()
        }
        crate::Protocol::WireGuardUdp => !peer.udp_ports.is_empty(),
        crate::Protocol::WireGuardTcp => !peer.tcp_ports.is_empty(),
        crate::Protocol::Stealth => !peer.tls_ports.is_empty(),
    };
    peers.iter().any(serves)
}

/// FR-32G/ER-11 (the bot round's P1): `InitialConnectionConfig` has
/// no separate protocol selector — a MANUAL request must constrain
/// every peer to that transport by CLEARING the non-selected port
/// lists (ProTUN stays free to pick any transport it can see; the
/// translated config shows it exactly one). Peers that cannot serve
/// the selected transport are OMITTED. Smart keeps every list
/// (ProTUN's own cycling is the feature).
fn constrain_transports(
    peers: Vec<PeerInfo>,
    protocol: crate::Protocol,
) -> Result<Vec<PeerInfo>, ProtocolError> {
    if matches!(protocol, crate::Protocol::Smart) {
        return Ok(peers);
    }
    let mut constrained = Vec::with_capacity(peers.len());
    for mut peer in peers {
        match protocol {
            crate::Protocol::WireGuardUdp => {
                peer.tcp_ports.clear();
                peer.tls_ports.clear();
                if peer.udp_ports.is_empty() {
                    continue;
                }
            }
            crate::Protocol::WireGuardTcp => {
                peer.udp_ports.clear();
                peer.tls_ports.clear();
                if peer.tcp_ports.is_empty() {
                    continue;
                }
            }
            crate::Protocol::Stealth => {
                peer.udp_ports.clear();
                peer.tcp_ports.clear();
                if peer.tls_ports.is_empty() {
                    continue;
                }
            }
            crate::Protocol::Smart => unreachable!("the Smart arm returned above"),
        }
        constrained.push(peer);
    }
    if constrained.is_empty() {
        return Err(ProtocolError::Unavailable(protocol));
    }
    Ok(constrained)
}

/// Decodes the base64 client key into ProTUN's fixed-size type. The
/// decoded intermediate is Zeroizing (NFR-16A: no unzeroized key
/// bytes on any path, including the length-error drop).
fn decode_client_key(key: &str) -> Result<WgClientPrivateKey, ProtocolError> {
    use base64::Engine;
    let bytes = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|error| {
                ProtocolError::InvalidKey(format!("client key is not base64: {error}"))
            })?,
    );
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolError::InvalidKey("client key is not 32 bytes".to_owned()))?;
    Ok(WgClientPrivateKey(array))
}

/// Decodes one peer's key and address into ProTUN's types.
fn decode_peer(peer: &crate::params::PeerParams) -> Result<PeerInfo, ProtocolError> {
    use base64::Engine;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&peer.public_key_base64)
        .map_err(|error| {
            ProtocolError::InvalidPeer(peer.id.clone(), format!("key is not base64: {error}"))
        })?;
    let server_public_key = WgPeerPublicKey::try_from(key_bytes).map_err(|_| {
        ProtocolError::InvalidPeer(peer.id.clone(), "key is not 32 bytes".to_owned())
    })?;
    Ok(PeerInfo {
        peer_id: peer.id.clone(),
        server_ip: IpAddress(peer.entry_ip),
        server_public_key,
        udp_ports: peer.udp_ports.clone(),
        tcp_ports: peer.tcp_ports.clone(),
        tls_ports: peer.tls_ports.clone(),
        priority: peer.priority,
        exit_label: peer.exit_label.clone(),
    })
}

/// Translates the peer list, refusing when NO well-formed peer
/// remains (a skipped malformed peer among healthy ones is a warn —
/// the connection cycles the healthy set).
fn translate_peers(peers: &[crate::params::PeerParams]) -> Result<Vec<PeerInfo>, ProtocolError> {
    let mut translated = Vec::with_capacity(peers.len());
    let mut last_error = None;
    for peer in peers {
        match decode_peer(peer) {
            Ok(info) => translated.push(info),
            Err(error) => {
                // Warn-and-proceed among healthy ones; the specific
                // error is kept for the none-remain refusal so it
                // names the last cause, not an empty id slot.
                tracing::warn!(peer = %peer.id, %error, "skipping malformed peer");
                last_error = Some(error);
            }
        }
    }
    if translated.is_empty() {
        return Err(last_error.unwrap_or_else(|| {
            ProtocolError::InvalidPeer(String::new(), "the peer set is empty".to_owned())
        }));
    }
    Ok(translated)
}

// The local_agent feature gate: PeerInfo.exit_label and the
// ConnectionMode::LocalAgent variant exist only under protun's
// `local-agent` feature, which the workspace pin enables — this
// module compiles against that surface.
#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use super::*;

    /// A well-formed 32-byte test key (base64 of 32 zero bytes... is
    /// NOT a valid X25519 key for real crypto, but ProTUN's type is
    /// an opaque byte array at this boundary — length is the only
    /// contract here).
    fn key_base64() -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([0u8; 32])
    }

    fn peer(id: &str, priority: i32) -> crate::params::PeerParams {
        use base64::Engine;
        // The PEER key is PUBLIC catalog data (no redaction needed)
        // but must DIFFER from the client-key fixture so the Debug
        // pin cannot pass on a collision.
        let peer_key = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        crate::params::PeerParams {
            id: id.to_owned(),
            entry_ip: IpAddr::from_str("192.0.2.10").unwrap(),
            public_key_base64: peer_key,
            udp_ports: vec![443, 1194],
            tcp_ports: vec![443],
            tls_ports: vec![8443],
            priority,
            exit_label: Some("CH#10".to_owned()),
        }
    }

    fn params(peers: Vec<crate::params::PeerParams>) -> TunnelParams {
        TunnelParams {
            peers,
            protocol: crate::Protocol::WireGuardUdp,
            network_available: true,
            client_private_key: Some(crate::params::ClientPrivateKey::new(key_base64())),
            sni_strategy: crate::params::SniStrategy::default(),
        }
    }

    #[test]
    fn translates_a_well_formed_peer_set_in_priority_order() {
        let config = translate(&params(vec![peer("a", 0), peer("b", 1)])).unwrap();
        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.peers[0].peer_id, "a");
        assert_eq!(config.peers[0].priority, 0);
        assert_eq!(config.peers[0].udp_ports, vec![443, 1194]);
        assert_eq!(config.peers[0].exit_label.as_deref(), Some("CH#10"));
        assert!(config.network_available);
    }

    #[test]
    fn a_missing_client_key_refuses_typed() {
        let mut request = params(vec![peer("a", 0)]);
        request.client_private_key = None;
        let error = translate(&request).unwrap_err();
        assert!(matches!(error, ProtocolError::MissingKey(_)), "{error}");
    }

    #[test]
    fn a_malformed_client_key_refuses_typed() {
        let mut request = params(vec![peer("a", 0)]);
        request.client_private_key = Some(crate::params::ClientPrivateKey::new(
            "not-base64!!!".to_owned(),
        ));
        assert!(matches!(
            translate(&request),
            Err(ProtocolError::InvalidKey(_))
        ));
        // Right base64, wrong length: refused too, never padded.
        let mut request = params(vec![peer("a", 0)]);
        request.client_private_key = Some(crate::params::ClientPrivateKey::new("AAAA".to_owned()));
        assert!(matches!(
            translate(&request),
            Err(ProtocolError::InvalidKey(_))
        ));
    }

    #[test]
    fn a_malformed_peer_among_healthy_ones_is_skipped() {
        let mut malformed = peer("bad", 1);
        malformed.public_key_base64 = "not-base64!!!".to_owned();
        let config = translate(&params(vec![peer("good", 0), malformed])).unwrap();
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].peer_id, "good");
    }

    #[test]
    fn the_only_peer_malformed_refuses_typed() {
        let mut malformed = peer("bad", 0);
        malformed.public_key_base64 = "not-base64!!!".to_owned();
        assert!(matches!(
            translate(&params(vec![malformed])),
            Err(ProtocolError::InvalidPeer(_, _))
        ));
    }

    #[test]
    fn the_empty_peer_set_refuses_typed() {
        assert!(matches!(
            translate(&params(Vec::new())),
            Err(ProtocolError::InvalidPeer(_, _))
        ));
    }

    #[test]
    fn serves_requested_protocol_matches_the_port_sets() {
        let mut udp_only = peer("a", 0);
        udp_only.tcp_ports.clear();
        udp_only.tls_ports.clear();
        let mut request = params(vec![udp_only]);
        assert!(request.serves_requested_protocol(), "UDP requested");
        request.protocol = crate::Protocol::WireGuardTcp;
        assert!(
            !request.serves_requested_protocol(),
            "no TCP ports — the pre-flight must refuse before the engine cycles dead"
        );
        request.protocol = crate::Protocol::Smart;
        assert!(request.serves_requested_protocol(), "any port serves Smart");

        // The Stealth arm and the all-ports-empty shape (the
        // OpenVPN-only physical: protun has no OpenVPN transport, so
        // it can serve nothing — false under every protocol).
        let mut tls_only = peer("b", 1);
        tls_only.udp_ports.clear();
        tls_only.tcp_ports.clear();
        let mut request = params(vec![tls_only]);
        request.protocol = crate::Protocol::Stealth;
        assert!(request.serves_requested_protocol(), "TLS requested");
        request.protocol = crate::Protocol::WireGuardUdp;
        assert!(!request.serves_requested_protocol());

        let mut dead = peer("c", 2);
        dead.udp_ports.clear();
        dead.tcp_ports.clear();
        dead.tls_ports.clear();
        let mut request = params(vec![dead]);
        request.protocol = crate::Protocol::Smart;
        assert!(
            !request.serves_requested_protocol(),
            "an OpenVPN-only physical serves nothing ProTUN speaks"
        );
    }

    /// The gate review's mutation pin: the malformed-FIRST path —
    /// pre-fix's condition (`translated.is_empty() && peers.len()
    /// == 1`) returned the specific error for a first-malformed
    /// among TWO, silently dropping the healthy peer; the rewritten
    /// loop warns and proceeds either way. Mutating the skip back to
    /// an early return fails THIS test.
    #[test]
    fn a_malformed_first_peer_among_healthy_ones_is_skipped() {
        let mut malformed = peer("bad", 0);
        malformed.public_key_base64 = "not-base64!!!".to_owned();
        let config = translate(&params(vec![malformed, peer("good", 1)])).unwrap();
        assert_eq!(config.peers.len(), 1, "the healthy peer survives");
        assert_eq!(config.peers[0].peer_id, "good");
    }

    /// Three peers, ALL malformed: the refusal names the LAST peer's
    /// specific error (not an empty id slot).
    #[test]
    fn an_all_malformed_peer_set_refuses_with_the_last_error() {
        let mut one = peer("one", 0);
        one.public_key_base64 = "not-base64!!!".to_owned();
        let mut two = peer("two", 1);
        two.public_key_base64 = "not-base64!!!".to_owned();
        let error = translate(&params(vec![one, two])).unwrap_err();
        match error {
            ProtocolError::InvalidPeer(id, _) => {
                assert_eq!(id, "two", "the last cause names its peer")
            }
            other => panic!("expected InvalidPeer, got {other}"),
        }
    }

    /// The dead-transport refusal fires AT the choke point (the gate
    /// review's defense-in-depth catch): translate refuses
    /// `Unavailable` for a request whose peers carry none of the
    /// requested transport's ports.
    #[test]
    fn translate_refuses_a_dead_transport_typed() {
        let mut udp_only = peer("a", 0);
        udp_only.tcp_ports.clear();
        udp_only.tls_ports.clear();
        let mut request = params(vec![udp_only]);
        request.protocol = crate::Protocol::Stealth;
        let error = translate(&request).unwrap_err();
        assert!(
            matches!(error, ProtocolError::Unavailable(crate::Protocol::Stealth)),
            "{error}"
        );
    }

    /// FR-7P/T-32: the private key never renders in Debug output —
    /// at BOTH layers now (the wrapper's own Debug and the params'
    /// manual impl).
    #[test]
    fn tunnel_params_debug_never_renders_the_key() {
        let rendered = format!("{:?}", params(vec![peer("a", 0)]));
        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(
            !rendered.contains(&key_base64()),
            "the key bytes must not appear: {rendered}"
        );
        let wrapper = format!("{:?}", crate::params::ClientPrivateKey::new(key_base64()));
        assert_eq!(wrapper, "ClientPrivateKey([redacted])");
    }

    /// The bot round's P1 (FR-32G/ER-11): a MANUAL request
    /// constrains every translated peer to that transport — the
    /// non-selected port lists are CLEARED (ProTUN sees exactly one
    /// transport) and peers that cannot serve it are OMITTED. Smart
    /// keeps every list (ProTUN's cycling is the feature).
    #[test]
    fn a_manual_request_constrains_every_peer_to_one_transport() {
        // UDP requested over a dual-transport peer: the tcp/tls lists
        // clear in the OUTPUT (the input keeps composing freedom).
        let config = translate(&params(vec![peer("dual", 0)])).unwrap();
        assert_eq!(config.peers[0].udp_ports, vec![443, 1194]);
        assert!(
            config.peers[0].tcp_ports.is_empty() && config.peers[0].tls_ports.is_empty(),
            "ProTUN must not see a non-requested transport: {:?}",
            config.peers[0]
        );

        // A peer that cannot serve the requested transport is
        // OMITTED; one that can survives.
        let mut tcp_only = peer("tcp-only", 1);
        tcp_only.udp_ports.clear();
        let config = translate(&params(vec![peer("udp-ok", 0), tcp_only])).unwrap();
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].peer_id, "udp-ok");

        // Smart keeps every list.
        let mut request = params(vec![peer("dual", 0)]);
        request.protocol = crate::Protocol::Smart;
        let config = translate(&request).unwrap();
        assert!(!config.peers[0].tcp_ports.is_empty());
        assert!(!config.peers[0].tls_ports.is_empty());
    }

    /// The bot round's P2: the post-skip recheck — the pre-flight
    /// passed over the RAW set on a malformed peer that was the only
    /// carrier of the requested transport; the recheck over the
    /// DECODED survivors refuses Unavailable instead of starting a
    /// dead cycle.
    #[test]
    fn the_only_transport_carrier_malformed_refuses_after_the_skip() {
        let mut malformed_carrier = peer("carrier", 0);
        malformed_carrier.public_key_base64 = "not-base64!!!".to_owned();
        // A well-formed peer WITHOUT UDP ports (the requested
        // transport): the pre-flight passes on the carrier's ports,
        // the skip drops the carrier, and the survivors cannot serve.
        let mut tcp_only = peer("tcp-only", 1);
        tcp_only.udp_ports.clear();
        let error = translate(&params(vec![malformed_carrier, tcp_only])).unwrap_err();
        assert!(
            matches!(
                error,
                ProtocolError::Unavailable(crate::Protocol::WireGuardUdp)
            ),
            "the recheck over the decoded set: {error}"
        );
    }

    /// The bot round's P2: the configured SNI strategy propagates —
    /// Top maps through (pre-fix Random was hard-coded, silently
    /// ignoring connection.protun.sni_strategy).
    #[test]
    fn the_configured_sni_strategy_propagates() {
        let mut request = params(vec![peer("a", 0)]);
        request.sni_strategy = crate::params::SniStrategy::Top;
        let config = translate(&request).unwrap();
        assert!(matches!(
            config.sni_strategy,
            protun::api::connection::SniStrategy::Top
        ));
        // The default stays Random.
        let config = translate(&params(vec![peer("a", 0)])).unwrap();
        assert!(matches!(
            config.sni_strategy,
            protun::api::connection::SniStrategy::Random
        ));
    }
}
