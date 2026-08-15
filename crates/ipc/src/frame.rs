//! Length-prefixed JSON frame codec.
//!
//! Frame layout: 4-byte big-endian payload length, then the JSON payload.
//! Frames above [`MAX_FRAME_LEN`] bytes are rejected to bound memory use.
//!
//! Two readers: the free functions ([`read_msg`]/[`read_frame`]) are
//! stateless and block until a whole frame arrived — right for clients and
//! writers. [`FrameReader`] additionally retains PARTIAL frame state across
//! `WouldBlock`/timed-out reads, which a polling server needs: discarding
//! half a frame on a poll timeout desynchronizes the session, because the
//! remaining bytes are then interpreted as a fresh length prefix (Codex PR
//! review finding 5, tracked as rust-review #12).
//!
//! [`FrameReader`] reads can also carry a caller-supplied deadline
//! ([`FrameReader::read_msg_within`]): a peer that trickles bytes faster
//! than the socket read timeout keeps every individual `read` succeeding,
//! so only a codec-level deadline bounds the total time one frame may take
//! (Codex PR review round 2, finding 2 — the server's hello phase).

use std::io::{Read, Write};
use std::time::Instant;

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
///
/// Stateless: a mid-frame timeout/error discards the bytes read so far.
/// Polling readers must use [`FrameReader`] instead.
pub fn read_msg<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, FrameError> {
    let payload = read_frame(r)?;
    serde_json::from_slice(&payload).map_err(|e| FrameError::Payload(e.to_string()))
}

/// Reads one raw frame payload, blocking until a whole frame arrived.
///
/// Stateless: a mid-frame timeout/error discards the bytes read so far.
/// Polling readers must use [`FrameReader`] instead.
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

/// Where a [`FrameReader`] stands inside the current frame.
enum Stage {
    /// Reading the 4-byte length prefix; `filled` bytes of it arrived.
    Prefix { buf: [u8; 4], filled: usize },
    /// Reading the payload; `filled` bytes of it arrived.
    Payload { buf: Vec<u8>, filled: usize },
}

/// Stateful frame reader that survives poll timeouts mid-frame.
///
/// A `WouldBlock`/timed-out read returns the I/O error like the free
/// functions do, but every byte already consumed stays buffered: the next
/// call resumes the SAME frame instead of misreading the remainder as a new
/// length prefix. Build one per connection (e.g. over a `&mut UnixStream`)
/// and reuse it for the connection's lifetime.
pub struct FrameReader<R> {
    inner: R,
    stage: Stage,
}

impl<R: Read> FrameReader<R> {
    /// Wraps a reader standing at a frame boundary.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            stage: Stage::Prefix {
                buf: [0u8; 4],
                filled: 0,
            },
        }
    }

    /// Reads one raw frame payload, resuming a partially read frame after
    /// a poll timeout.
    pub fn read_frame(&mut self) -> Result<Vec<u8>, FrameError> {
        self.read_frame_deadline(None)
    }

    /// [`FrameReader::read_frame`] bounded by `deadline`.
    ///
    /// Fails with `TimedOut` once the deadline passes EVEN IF bytes keep
    /// arriving: each successful `read` resets the socket-level timeout,
    /// so a peer dribbling one byte per sub-timeout interval would
    /// otherwise stretch a single frame out indefinitely. Partial
    /// progress is retained, so a caller may still resume the frame with
    /// [`FrameReader::read_frame`].
    pub fn read_frame_within(&mut self, deadline: Instant) -> Result<Vec<u8>, FrameError> {
        self.read_frame_deadline(Some(deadline))
    }

    fn read_frame_deadline(&mut self, deadline: Option<Instant>) -> Result<Vec<u8>, FrameError> {
        loop {
            match &mut self.stage {
                Stage::Prefix { buf, filled } => {
                    fill(&mut self.inner, buf, filled, deadline)?;
                    let len = u32::from_be_bytes(*buf) as usize;
                    if len > MAX_FRAME_LEN {
                        // The stream is untrustworthy past this point;
                        // reset so a fresh connection state is at least
                        // well-defined if a caller retries.
                        self.stage = Stage::Prefix {
                            buf: [0u8; 4],
                            filled: 0,
                        };
                        return Err(FrameError::TooLarge(len));
                    }
                    self.stage = Stage::Payload {
                        buf: vec![0u8; len],
                        filled: 0,
                    };
                }
                Stage::Payload { buf, filled } => {
                    fill(&mut self.inner, buf, filled, deadline)?;
                    // Stage completed: hand over the payload and stand at
                    // the next frame boundary.
                    return match std::mem::replace(
                        &mut self.stage,
                        Stage::Prefix {
                            buf: [0u8; 4],
                            filled: 0,
                        },
                    ) {
                        Stage::Payload { buf, .. } => Ok(buf),
                        _ => unreachable!("matched Payload above"),
                    };
                }
            }
        }
    }

    /// [`FrameReader::read_frame`] plus JSON deserialization.
    pub fn read_msg<T: DeserializeOwned>(&mut self) -> Result<T, FrameError> {
        let payload = self.read_frame()?;
        serde_json::from_slice(&payload).map_err(|e| FrameError::Payload(e.to_string()))
    }

    /// [`FrameReader::read_msg`] bounded by `deadline` — see
    /// [`FrameReader::read_frame_within`].
    pub fn read_msg_within<T: DeserializeOwned>(
        &mut self,
        deadline: Instant,
    ) -> Result<T, FrameError> {
        let payload = self.read_frame_within(deadline)?;
        serde_json::from_slice(&payload).map_err(|e| FrameError::Payload(e.to_string()))
    }

    /// Unwraps into the underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Advances `filled` toward `buf.len()` on `r`, leaving partial progress
/// intact for the caller to resume after a poll timeout.
///
/// With `deadline` set, the loop also fails with `TimedOut` once the
/// deadline passes — checked before every `read`, so a steady dribble of
/// successfully arriving bytes cannot outlive it (Codex PR review round 2,
/// finding 2).
fn fill<R: Read>(
    r: &mut R,
    buf: &mut [u8],
    filled: &mut usize,
    deadline: Option<Instant>,
) -> Result<(), FrameError> {
    while *filled < buf.len() {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            return Err(FrameError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "frame deadline exceeded while bytes kept arriving",
            )));
        }
        match r.read(&mut buf[*filled..]) {
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => *filled += n,
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

    /// A reader that hands out one chunk at a time and fails with
    /// `WouldBlock` between chunks — the wire equivalent of a slow peer
    /// A reader that hands out one chunk at a time and fails with
    /// `WouldBlock` between chunks — the wire equivalent of a slow peer
    /// observed through a read-timeout poller.
    struct Trickle {
        chunks: Vec<Vec<u8>>,
        fail_next: bool,
    }

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.fail_next {
                self.fail_next = false;
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            let Some(chunk) = self.chunks.first() else {
                // Idle connection: nothing more has arrived yet.
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            };
            let n = chunk.len().min(buf.len());
            buf[..n].copy_from_slice(&chunk[..n]);
            if n == chunk.len() {
                self.chunks.remove(0);
            } else {
                self.chunks[0] = chunk[n..].to_vec();
            }
            self.fail_next = true;
            Ok(n)
        }
    }

    /// Codex PR review finding 5: partial-frame state must survive
    /// WouldBlock between chunks — including a stall in the middle of the
    /// 4-byte length prefix itself.
    #[test]
    fn frame_reader_resumes_partial_frames_across_wouldblock() {
        let mut frame = Vec::new();
        write_msg(&mut frame, &serde_json::json!({ "split": true })).unwrap();
        assert!(frame.len() > 8, "payload must be split-able");

        // Byte-by-byte prefix stall, then a payload split in half.
        let payload_half = 4 + (frame.len() - 4) / 2;
        let mut reader = FrameReader::new(Trickle {
            chunks: vec![
                frame[..1].to_vec(),
                frame[1..3].to_vec(),
                frame[3..4].to_vec(),
                frame[4..payload_half].to_vec(),
                frame[payload_half..].to_vec(),
            ],
            fail_next: false,
        });
        let mut would_blocks = 0;
        let payload = loop {
            match reader.read_frame() {
                Ok(payload) => break payload,
                Err(FrameError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    would_blocks += 1;
                    assert!(would_blocks < 32, "reader is spinning, not resuming");
                }
                other => panic!("unexpected result mid-frame: {other:?}"),
            }
        };
        assert!(would_blocks >= 4, "the trickle must have stalled mid-frame");
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(value["split"], true);

        // And the very next frame still lines up.
        let mut second = Vec::new();
        write_msg(&mut second, &serde_json::json!([1u8, 2, 3])).unwrap();
        let mut reader = FrameReader::new(Trickle {
            chunks: vec![second[..2].to_vec(), second[2..].to_vec()],
            fail_next: false,
        });
        let payload = loop {
            match reader.read_frame() {
                Ok(payload) => break payload,
                Err(FrameError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                other => panic!("unexpected result mid-frame: {other:?}"),
            }
        };
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(value.as_array().map(Vec::len), Some(3));
    }

    /// Codex PR review round 2, finding 2: a STEADY dribble — one byte per
    /// successful read, never a WouldBlock in between — must not outlive a
    /// caller-supplied deadline. Each successful read resets the socket
    /// timeout, so only the codec-level deadline bounds the frame's total
    /// duration; partial progress is retained for resumption.
    #[test]
    fn deadline_bounds_a_steady_trickle_mid_frame() {
        struct SteadyDribble {
            data: Vec<u8>,
            pos: usize,
        }
        impl Read for SteadyDribble {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.pos >= self.data.len() {
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                std::thread::sleep(std::time::Duration::from_micros(200));
                buf[0] = self.data[self.pos];
                self.pos += 1;
                Ok(1)
            }
        }

        let payload = "x".repeat(4096);
        let mut frame = Vec::new();
        write_msg(&mut frame, &serde_json::json!(&payload)).unwrap();

        let deadline = Instant::now() + std::time::Duration::from_millis(50);
        let mut reader = FrameReader::new(SteadyDribble {
            data: frame.clone(),
            pos: 0,
        });
        let err = reader
            .read_frame_within(deadline)
            .expect_err("the deadline must fire mid-dribble");
        assert!(
            matches!(&err, FrameError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut),
            "expected a TimedOut failure, got {err:?}"
        );

        // Partial progress survived: the same reader resumes and completes
        // the SAME frame afterwards.
        let resumed = reader
            .read_frame()
            .expect("frame resumes after the deadline");
        let value: serde_json::Value = serde_json::from_slice(&resumed).unwrap();
        assert_eq!(value.as_str(), Some(payload.as_str()));
    }
}
