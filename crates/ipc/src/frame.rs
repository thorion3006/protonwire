//! Length-prefixed JSON frame codec.
//!
//! Frame layout: 4-byte big-endian payload length, then the JSON payload.
//! Frames above [`MAX_FRAME_LEN`] bytes are rejected to bound memory use.

use std::io::{Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Upper bound for a single frame payload (1 MiB).
pub const MAX_FRAME_LEN: usize = 1 << 20;

/// Errors produced by the frame codec.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The peer sent a length prefix above [`MAX_FRAME_LEN`].
    #[error("frame of {0} bytes exceeds the {MAX_FRAME_LEN}-byte limit")]
    TooLarge(usize),
    /// The connection closed mid-frame or mid-prefix.
    #[error("connection closed mid-frame")]
    Truncated,
    /// The payload failed JSON (de)serialization.
    #[error("frame payload is not valid for the expected type: {0}")]
    Payload(String),
    /// Underlying socket I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Writes one framed message.
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), FrameError> {
    let payload = serde_json::to_vec(msg).map_err(|e| FrameError::Payload(e.to_string()))?;
    if payload.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let len = u32::try_from(payload.len()).expect("checked against MAX_FRAME_LEN");
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&payload)?;
    w.flush()?;
    Ok(())
}

/// Reads one framed message, blocking until a whole frame arrived.
pub fn read_msg<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, FrameError> {
    let payload = read_frame(r)?;
    serde_json::from_slice(&payload).map_err(|e| FrameError::Payload(e.to_string()))
}

/// Reads one raw frame payload, blocking until a whole frame arrived.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut prefix = [0u8; 4];
    read_exact_or_truncated(r, &mut prefix)?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut payload = vec![0u8; len];
    read_exact_or_truncated(r, &mut payload)?;
    Ok(payload)
}

/// `Read::read_exact` that maps EOF mid-buffer to [`FrameError::Truncated`]
/// and propagates timeouts as `WouldBlock` so callers can poll.
fn read_exact_or_truncated<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), FrameError> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &serde_json::json!({ "a": 1 })).unwrap();
        let back: serde_json::Value = read_msg(&mut buf.as_slice()).unwrap();
        assert_eq!(back["a"], 1);
    }

    #[test]
    fn oversize_frame_rejected_on_read() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_FRAME_LEN + 1) as u32).to_be_bytes());
        let err = read_frame(&mut buf.as_slice()).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(n) if n == MAX_FRAME_LEN + 1));
    }

    #[test]
    fn oversize_frame_rejected_on_write() {
        let huge = "x".repeat(MAX_FRAME_LEN + 1);
        let mut buf = Vec::new();
        let err = write_msg(&mut buf, &serde_json::json!(huge)).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
    }

    #[test]
    fn truncated_frame_detected() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &serde_json::json!(vec![1u8; 64])).unwrap();
        buf.truncate(buf.len() - 10);
        let err = read_frame(&mut buf.as_slice()).unwrap_err();
        assert!(matches!(err, FrameError::Truncated));
    }

    #[test]
    fn invalid_payload_rejected() {
        let mut buf = Vec::new();
        let payload = b"not json";
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        let err = read_msg::<_, serde_json::Value>(&mut buf.as_slice()).unwrap_err();
        assert!(matches!(err, FrameError::Payload(_)));
    }
}
