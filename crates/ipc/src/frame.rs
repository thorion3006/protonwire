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
//!
//! The write side has the mirror-image exposure ([`write_msg_within`],
//! R7-1): `SO_SNDTIMEO` cannot bound a MESSAGE, for two measured reasons
//! (sec round-7 probe; the round-5 instrumented run is recorded in
//! docs/review-log.md's SO_SNDTIMEO track item). First, it bounds each
//! WAIT, not the message: progress resets it, and a multi-syscall write
//! multiplies it — a 0.9 MiB frame is ~4 syscalls, i.e. up to ~4x the
//! configured timeout for one message. Second, under steady drain it
//! NEVER expires: every dribbled byte that frees space starts a fresh
//! wait (the probe watched a draining peer stretch past 80 s under a
//! 1 s timeout). Only a whole-message userspace deadline bounds the
//! frame.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
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

/// [`write_msg`] bounded by `deadline` — the write-side mirror of
/// [`FrameReader::read_msg_within`] (R7-1, round-5 track item).
///
/// `SO_SNDTIMEO` cannot carry this bound, for the two measured reasons
/// of the module-level record (sec round-7 probe; round-5 instrumented
/// evidence in docs/review-log.md's SO_SNDTIMEO track item): it bounds
/// each WAIT, not the message — progress resets it, and a multi-syscall
/// write multiplies it (a 0.9 MiB frame is ~4 syscalls, so up to ~4x the
/// configured timeout for one message) — and under steady drain it never
/// expires at all, because each dribbled byte that frees space starts a
/// fresh wait (80+ s watched under a 1 s timeout). Each chunk is
/// therefore sent with `MSG_DONTWAIT`, so the syscall itself can never
/// block; poll(2) paces the retries and waits no longer than the
/// deadline's remaining budget. Expiry fails with
/// [`std::io::ErrorKind::TimedOut`]; partial progress does NOT reset the
/// deadline (one message, one budget).
///
/// Takes [`AsFd`] only: every byte goes out through `send(fd, MSG_DONTWAIT)`
/// in [`write_all_within`], so `std::io::Write` is never used (a `flush`
/// would be a no-op on a socket anyway) and advertising the bound would
/// imply a stdio-style writer is acceptable here.
pub fn write_msg_within<W: AsFd, T: Serialize>(
    w: &mut W,
    msg: &T,
    deadline: Instant,
) -> Result<(), FrameError> {
    let payload = serde_json::to_vec(msg).map_err(|e| FrameError::Payload(e.to_string()))?;
    if payload.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let len = u32::try_from(payload.len()).expect("checked against MAX_FRAME_LEN");
    write_all_within(w, &len.to_be_bytes(), deadline)?;
    write_all_within(w, &payload, deadline)?;
    Ok(())
}

/// `Write::write_all` that never enters a send it cannot leave: every
/// chunk goes out with `MSG_DONTWAIT` (nonblocking for this one syscall,
/// whatever the fd's flags — so clones of the socket keep their blocking
/// semantics), retries are paced by poll(2) inside the remaining budget,
/// and expiry fails with `TimedOut`.
fn write_all_within<W: AsFd>(w: &mut W, buf: &[u8], deadline: Instant) -> Result<(), FrameError> {
    use nix::poll::{PollFd, PollFlags, poll};
    use nix::sys::socket::{MsgFlags, send};

    let mut written = 0;
    while written < buf.len() {
        let now = Instant::now();
        if now >= deadline {
            return Err(write_deadline_exceeded());
        }
        // poll(2) rounds to whole milliseconds and nix's PollTimeout tops
        // out at u16; a sub-millisecond budget still gets one poll so a
        // just-writable socket is not failed spuriously, and a budget past
        // the u16 range is clamped — expiry is re-checked at the loop top
        // regardless, so a clamped poll merely waits in 65 s slices.
        let budget_ms = ((deadline - now).as_millis().min(u16::MAX as u128) as u16).max(1);
        let mut writable = [PollFd::new(w.as_fd(), PollFlags::POLLOUT)];
        match poll(&mut writable, budget_ms) {
            // Budget slice spent with no writability — NOT automatically
            // the deadline's answer: a budget past the u16 range was
            // clamped, so the spent slice can end well BEFORE the deadline
            // (a 70 s deadline clamps to a ~65.5 s slice). Re-enter the
            // loop and let the deadline check at the top decide: a spent
            // real budget expires there on the very next pass, while a
            // clamped slice re-polls inside whatever remains.
            Ok(0) => continue,
            // Writable, or POLLERR/POLLHUP — the send attempt below
            // surfaces the peer's error instead of guessing at revents.
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(FrameError::Io(std::io::Error::other(e.to_string()))),
        }
        match send(
            w.as_fd().as_raw_fd(),
            &buf[written..],
            MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(0) => {
                return Err(FrameError::Io(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "writer wrote zero bytes",
                )));
            }
            Ok(n) => written += n,
            // The writable race lost (or the moment passed): re-poll
            // within the remaining budget rather than spinning.
            Err(nix::errno::Errno::EAGAIN) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(FrameError::Io(std::io::Error::other(e.to_string()))),
        }
    }
    Ok(())
}

/// The R7-1 expiry error: named so callers can distinguish "the peer
/// stalled past the deadline" from a generic socket failure.
fn write_deadline_exceeded() -> FrameError {
    FrameError::Io(std::io::Error::new(
        ErrorKind::TimedOut,
        "frame write deadline exceeded while the peer stalled",
    ))
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

    /// R7-1: a write to a never-reading peer must fail at the WHOLE-MESSAGE
    /// deadline, in userspace — not lean on `SO_SNDTIMEO`, which bounds
    /// each WAIT, not the message: progress resets it, a multi-syscall
    /// write multiplies it (a 0.9 MiB frame is ~4 syscalls), and under
    /// steady drain it never expires at all (sec round-7 probe; the
    /// round-5 instrumented run is recorded in docs/review-log.md's
    /// SO_SNDTIMEO track item).
    #[test]
    fn write_msg_within_fails_at_the_deadline_against_a_stalled_peer() {
        let (mut a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        nix::sys::socket::setsockopt(&b, nix::sys::socket::sockopt::RcvBuf, &4096usize)
            .expect("SO_RCVBUF applies");
        let deadline = Instant::now() + std::time::Duration::from_millis(300);
        let payload = "x".repeat(900_000);
        let started = Instant::now();
        let err = write_msg_within(&mut a, &serde_json::json!(payload), deadline)
            .expect_err("a never-reading 4 KiB peer must expire the write");
        assert!(
            matches!(&err, FrameError::Io(e) if e.kind() == ErrorKind::TimedOut),
            "expected a TimedOut failure, got {err:?}"
        );
        // The budget is honored from both sides: never before the
        // deadline (the loop only fails once it is spent)...
        assert!(
            started.elapsed() + std::time::Duration::from_millis(10)
                >= std::time::Duration::from_millis(300),
            "the write failed before its own deadline: {:?}",
            started.elapsed()
        );
        // ...and not much after it (one deadline for one message, not a
        // multiple of per-syscall waits).
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the deadline must bound the write, took {:?}",
            started.elapsed()
        );
    }

    /// R7-1: a draining peer keeps the writes SUCCEEDING — the frame
    /// completes when, and only when, the whole transfer fits inside the
    /// one deadline budget; partial progress never resets it.
    #[test]
    fn write_msg_within_completes_when_the_peer_drains() {
        use std::io::Read;

        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        nix::sys::socket::setsockopt(&b, nix::sys::socket::sockopt::RcvBuf, &4096usize)
            .expect("SO_RCVBUF applies");

        // The big frame forces many partial writes through the 4 KiB
        // receive window; a follow-up small frame proves the stream stays
        // synchronized afterwards.
        let big = "x".repeat(300_000);
        let mut expected = Vec::new();
        write_msg(&mut expected, &serde_json::json!(&big)).unwrap();
        let expected = expected.len();

        let reader = std::thread::spawn(move || {
            let mut got = 0;
            let mut chunk = [0u8; 16_384];
            while got < expected {
                got += b.read(&mut chunk).expect("peer keeps draining");
            }
            let follow_up: serde_json::Value =
                read_msg(&mut b).expect("the follow-up frame arrives");
            follow_up
        });

        let generous = Instant::now() + std::time::Duration::from_secs(5);
        write_msg_within(&mut a, &serde_json::json!(&big), generous)
            .expect("a draining peer accepts the frame inside the budget");
        write_msg_within(&mut a, &serde_json::json!({ "done": true }), generous)
            .expect("the follow-up frame writes");

        let follow_up = reader.join().unwrap();
        assert_eq!(follow_up["done"], true);
    }

    /// Rust-review round 7 (poll-clamp finding): a deadline MORE than one
    /// clamped poll slice away (poll budgets top out at u16::MAX ms ≈
    /// 65.5 s) must not expire the write early. The reachable variant: a
    /// 70 s deadline — the shape a large `IpcClient::set_timeout` (or
    /// `ProtonwireClient::set_request_timeout`) produces — against a
    /// healthy, writable peer completes immediately.
    ///
    /// Honest disclosure: this test ALSO passes pre-fix. The bug's trigger
    /// needs the socket to stay unwritable for a full clamped slice
    /// (~65.5 s of stall), which cannot be wall-clock tested; the pre-fix
    /// `Ok(0) => return Err(write_deadline_exceeded())` expired such a
    /// write at ~65.5 s of a 70 s budget — evidence is code inspection
    /// plus the existing stalled-peer deadline tests
    /// (`write_msg_within_fails_at_the_deadline_against_a_stalled_peer`)
    /// staying green, which pin that a spent REAL budget still expires.
    #[test]
    fn write_msg_within_completes_with_a_budget_past_the_poll_clamp() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        // 70 s is past the clamp: the first poll slice is clamped to
        // u16::MAX ms, and pre-fix that slice's timeout was mistaken for
        // the deadline's answer.
        let deadline = Instant::now() + std::time::Duration::from_secs(70);
        let started = Instant::now();
        write_msg_within(&mut a, &serde_json::json!({ "clamp": true }), deadline)
            .expect("a healthy peer completes the write regardless of the clamp");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the write must complete immediately against a writable peer, took {:?}",
            started.elapsed()
        );
        let back: serde_json::Value = read_msg(&mut b).unwrap();
        assert_eq!(back["clamp"], true);
    }
}
