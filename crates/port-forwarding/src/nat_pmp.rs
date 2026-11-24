//! The NAT-PMP wire protocol (RFC 6886) — the public-port mapping
//! request (opcode 2) and its response, as pure encode/decode over
//! byte buffers. No socket: the transport owns the UDP exchange and
//! feeds the decoded [`MappingResponse`] into the lease FSM.
//!
//! Wire shapes (all big-endian per RFC 6886):
//! - request:  version(0) opcode(2) reserved(u16) proposed_external(u16)
//!   lifetime(u32) — 12 bytes;
//! - response: version(0) opcode(130) result_code(u16) seconds_since_epoch
//!   (u32) public_port(u16) lifetime(u32) — 16 bytes.

use crate::lease::Mapping;

/// The NAT-PMP protocol version (RFC 6886: version 0).
const VERSION: u8 = 0;
/// The public-port mapping request opcode.
const OPCODE_MAP_PUBLIC_PORT: u8 = 2;
/// The response opcode is the request opcode + 128.
const RESPONSE_OPCODE_BASE: u8 = 128;
/// The RFC 6886 success result code.
const RESULT_SUCCESS: u16 = 0;

/// A decoded gateway answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingResponse {
    /// The RFC 6886 result code (0 = success).
    pub result_code: u16,
    /// The gateway's seconds-since-epoch (lease FSM alignment input).
    pub seconds_since_epoch: u32,
    /// The external port the gateway assigned.
    pub public_port: u16,
    /// The server-declared lease lifetime in seconds.
    pub lifetime_secs: u32,
}

/// Encodes a public-port mapping request for `proposed_port` with the
/// RFC-recommended 7200-second lifetime. Exactly 12 bytes, version 0,
/// opcode 2.
pub fn encode_map_request(proposed_port: u16) -> [u8; 12] {
    let mut packet = [0u8; 12];
    packet[0] = VERSION;
    packet[1] = OPCODE_MAP_PUBLIC_PORT;
    packet[4..6].copy_from_slice(&proposed_port.to_be_bytes());
    // lifetime 7200 s (RFC 6886's recommendation).
    packet[8..12].copy_from_slice(&7200u32.to_be_bytes());
    packet
}

/// Decodes a 16-byte gateway response. Refuses anything that is not a
/// public-port MAPPING response (wrong version, wrong opcode, wrong
/// length) — the transport feeds only real answers here, and a
/// refusal is the caller's signal to treat the exchange as failed.
pub fn decode_mapping_response(bytes: &[u8]) -> Option<MappingResponse> {
    if bytes.len() != 16 {
        return None;
    }
    if bytes[0] != VERSION {
        return None;
    }
    if bytes[1] != OPCODE_MAP_PUBLIC_PORT + RESPONSE_OPCODE_BASE {
        return None;
    }
    Some(MappingResponse {
        result_code: u16::from_be_bytes([bytes[2], bytes[3]]),
        seconds_since_epoch: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        public_port: u16::from_be_bytes([bytes[12], bytes[13]]),
        lifetime_secs: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
    })
}

/// Whether a decoded response is a SUCCESS the lease FSM can consume
/// (result code 0 maps onto [`Mapping`]; anything else is the
/// gateway refusing — the caller reports it as a renewal/request
/// failure).
pub fn success(response: &MappingResponse) -> Option<Mapping> {
    if response.result_code != RESULT_SUCCESS {
        return None;
    }
    Some(Mapping {
        public_port: response.public_port,
        lifetime: std::time::Duration::from_secs(u64::from(response.lifetime_secs)),
        gateway_epoch: response.seconds_since_epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request wire shape, byte for byte: version 0, opcode 2,
    /// reserved zero, the proposed port, the 7200-second lifetime —
    /// all big-endian.
    #[test]
    fn the_map_request_encodes_the_rfc_6886_shape() {
        let bytes = encode_map_request(54321);
        assert_eq!(bytes.len(), 12);
        assert_eq!(bytes[0], 0, "version");
        assert_eq!(bytes[1], 2, "opcode: public-port map");
        assert_eq!(&bytes[2..4], &[0, 0], "reserved");
        assert_eq!(bytes[4..6], 54321u16.to_be_bytes(), "proposed port");
        assert_eq!(bytes[8..12], 7200u32.to_be_bytes(), "lifetime");
    }

    /// A successful response decodes into the mapping the FSM
    /// consumes: result, epoch, port, lifetime.
    #[test]
    fn a_success_response_decodes_fully() {
        let mut bytes = [0u8; 16];
        bytes[0] = 0; // version
        bytes[1] = 2 + 128; // response opcode
        bytes[2..4].copy_from_slice(&0u16.to_be_bytes()); // success
        bytes[4..8].copy_from_slice(&1_700_000_000u32.to_be_bytes()); // epoch
        bytes[8..12].copy_from_slice(&7200u32.to_be_bytes()); // lifetime
        bytes[12..14].copy_from_slice(&61234u16.to_be_bytes()); // public port

        let response = decode_mapping_response(&bytes).expect("a well-formed response");
        assert_eq!(response.result_code, 0);
        assert_eq!(response.seconds_since_epoch, 1_700_000_000);
        assert_eq!(response.public_port, 61234);
        assert_eq!(response.lifetime_secs, 7200);
        assert_eq!(
            success(&response).expect("success maps onto the FSM type"),
            Mapping {
                public_port: 61234,
                lifetime: std::time::Duration::from_secs(7200),
                gateway_epoch: 1_700_000_000,
            }
        );
    }

    /// Refusals: wrong length, wrong version, wrong opcode — each is
    /// the caller's exchange-failure signal, never a guessed mapping.
    #[test]
    fn malformed_responses_refuse() {
        assert!(decode_mapping_response(&[0u8; 15]).is_none(), "short");
        assert!(decode_mapping_response(&[0u8; 17]).is_none(), "long");
        let mut wrong_version = [0u8; 16];
        wrong_version[0] = 1;
        assert!(decode_mapping_response(&wrong_version).is_none(), "version");
        let mut wrong_opcode = [0u8; 16];
        wrong_opcode[1] = 3 + 128; // a different response opcode
        assert!(decode_mapping_response(&wrong_opcode).is_none(), "opcode");
    }

    /// A nonzero result code decodes but is NOT a success — the FSM
    /// sees a renewal failure (e.g. 4 = out of resources).
    #[test]
    fn a_nonzero_result_code_is_not_a_success() {
        let mut bytes = [0u8; 16];
        bytes[1] = 2 + 128;
        bytes[2..4].copy_from_slice(&4u16.to_be_bytes()); // out of resources
        bytes[12..14].copy_from_slice(&61234u16.to_be_bytes());
        let response = decode_mapping_response(&bytes).expect("well formed");
        assert!(success(&response).is_none(), "a refusal maps to no Mapping");
    }
}
