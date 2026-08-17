//! One accepted client connection: the hello handshake, the request
//! dispatch loop and its R9-2 request-credit window, the writer
//! thread, and the teardown ordering that guarantees bus-slot release.

use std::io;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use protonwire_frontend_api::{
    ClientMessage, EVENT_SEQ_RESYNC_NOW, Event, EventEnvelope, HelloAck, HelloError, NoticeLevel,
    PROTOCOL_VERSION, Request, RequestResult, Response, RpcError, ServerMessage,
};
use tracing::{debug, info, warn};

use crate::authz::{authorize, required_role};
use crate::bus::EventBus;
use crate::frame::{FrameError, FrameReader, write_msg_within};
use crate::peer::PeerCredentials;
use crate::server::{
    MAX_UNWRITTEN_MESSAGES, READ_POLL, RequestHandler, SessionContext, WRITE_WINDOW_POLL,
};

/// The end-of-burst overflow marker (X4): a `ServerMessage::Event` whose
/// seq is the reserved [`EVENT_SEQ_RESYNC_NOW`], carrying a real
/// [`Event::Notice`] payload so the frame deserializes on every client —
/// including ones that predate the signal. RELEASE builds of such an SDK
/// self-recover: the impossible seq reads as a gap, and the wrapped
/// cursor heals after one spurious resync (verified by both reviewers).
/// DEBUG builds of a pre-signal SDK panicked on the cursor+1 overflow —
/// current SDKs intercept the envelope before any cursor arithmetic, and
/// the arithmetic itself is checked_add since rust-review round 8, so no
/// build sits one add from a panic. Fully gating the marker behind the
/// hello handshake remains a TRACK ITEM with sec's hard trigger:
/// must-fix before any separately-shipped client artifact.
fn resync_marker() -> ServerMessage {
    ServerMessage::Event(EventEnvelope {
        seq: EVENT_SEQ_RESYNC_NOW,
        event: Event::Notice {
            level: NoticeLevel::Warning,
            message: "event queue overflowed; resynchronize".into(),
        },
    })
}

/// Serves one client connection until EOF, error, or daemon shutdown.
pub(super) fn handle_session<H: RequestHandler>(
    stream: Arc<UnixStream>,
    handler: Arc<H>,
    stop: Arc<AtomicBool>,
    hello_deadline: Duration,
    write_timeout: Duration,
) {
    // The session slot the accept loop reserved is released on EVERY exit
    // path — early rejects below, dispatcher panics (the serve loop's
    // catch_unwind drops this guard during unwind), and normal teardown
    // (Codex PR review finding 2).
    struct ReleaseSlotOnDrop<'a>(&'a EventBus);
    impl Drop for ReleaseSlotOnDrop<'_> {
        fn drop(&mut self) {
            self.0.release_session();
        }
    }
    let _slot = ReleaseSlotOnDrop(handler.event_bus());
    let Ok(peer) = PeerCredentials::of(&stream) else {
        debug!("session rejected: peer credentials unavailable");
        return;
    };
    if let Err(e) = stream.set_read_timeout(Some(READ_POLL)) {
        warn!("set_read_timeout failed: {e}");
        return;
    };
    let Ok(mut read_half) = stream.try_clone() else {
        warn!("session rejected: socket clone failed");
        return;
    };

    // Writer thread owns a socket handle exclusively; the write ceiling is
    // enforced per-message by the userspace watchdog in the writer loop
    // below, with this syscall-level timeout as a backstop for any send
    // that slips past the poll. Socket options are shared with every clone
    // of the socket, so the timeouts set here govern the reader and the
    // drain handle alike.
    if let Err(e) = stream.set_write_timeout(Some(write_timeout)) {
        warn!("set_write_timeout failed: {e}");
        return;
    }
    let (writer_tx, writer_rx) = mpsc::sync_channel::<ServerMessage>(crate::bus::SESSION_QUEUE_LEN);
    // R9-2: the request-credit window shared by every sender into the
    // writer channel (dispatcher, forwarder) and the writer itself — see
    // [`WriteWindow`] and [`MAX_UNWRITTEN_MESSAGES`] for the bound and its
    // arithmetic.
    let window = Arc::new(WriteWindow::new());
    let writer_window = Arc::clone(&window);
    let write_stream = stream;
    let writer = std::thread::spawn(move || {
        let mut write_half = &*write_stream;
        for message in writer_rx {
            // R7-1 (round-5 track item, P1): every message gets the full
            // write ceiling as a USERSPACE deadline — `SO_SNDTIMEO`
            // bounds each WAIT, not the message (progress resets it; a
            // 0.9 MiB frame is ~4 syscalls, so the waits multiply), and
            // under steady drain it never expires at all (sec round-7
            // probe). Expiry fails the write, the loop breaks, and the
            // teardown below fires.
            let deadline = Instant::now() + write_timeout;
            if write_msg_within(&mut write_half, &message, deadline).is_err() {
                break;
            }
            // On the wire: release the message's window slot so the
            // dispatcher may read another request. A write failure breaks
            // WITHOUT releasing — the slot's message is dead but the
            // writer is dying too, and the exit note below unparks any
            // dispatcher waiting on the window.
            writer_window.release();
        }
        // Announce death BEFORE the channel receiver drops at scope exit:
        // from that moment every sender's send fails, but a dispatcher
        // parked on the WINDOW never sends — only this flag (checked on
        // every window poll) tells it the counter can no longer decrease.
        writer_window.note_writer_exit();
        // A dead writer takes the session with it (Codex round 5, P1):
        // every clone shares ONE socket, so shutting it down here also
        // fails the dispatcher's read half and drives `serve_messages`
        // through the normal teardown (unsubscribe + slot release).
        // Without this, a client that triggers the write ceiling with an
        // oversized response and then merely holds its side open keeps
        // its reserved session slot forever — 64 such connections wedge
        // the daemon at MAX_SESSIONS. On normal teardown the socket is
        // already closing, so the extra shutdown is a no-op there.
        let _ = write_stream.shutdown(Shutdown::Both);
    });

    let (session_id, event_rx, overflowed) = handler.event_bus().subscribe();
    // Drop-guard: unsubscribe runs on every exit path, including panics in
    // the dispatcher below.
    struct UnsubscribeOnDrop<'a> {
        bus: &'a EventBus,
        id: u64,
    }
    impl Drop for UnsubscribeOnDrop<'_> {
        fn drop(&mut self) {
            self.bus.unsubscribe(self.id);
        }
    }
    let _guard = UnsubscribeOnDrop {
        bus: handler.event_bus(),
        id: session_id,
    };
    // pr-champion WO-5: the forwarder is gated so nothing it holds can
    // reach the wire before the hello ack. Subscribe() happens before the
    // handshake on purpose (events published mid-handshake must not be
    // lost), but unguarded the forwarder raced them onto the socket ahead
    // of HelloAck — and a client rejects any non-ack frame while
    // handshaking. The gate opens only after the ack is queued; a session
    // that ends pre-hello drops `gate_tx`, which unblocks (and ends) the
    // forwarder instead of stranding it on the closed gate.
    let (gate_tx, gate_rx) = mpsc::sync_channel::<()>(1);
    let event_forward = {
        let forward_tx = writer_tx.clone();
        let forward_window = Arc::clone(&window);
        let overflowed = Arc::clone(&overflowed);
        std::thread::spawn(move || {
            if gate_rx.recv().is_err() {
                return; // session ended before hello; nothing to forward
            }
            for message in event_rx {
                if forward_window.send_through(&forward_tx, message).is_err() {
                    break;
                }
                // X4 (round 8): answer an end-of-burst overflow without a
                // later publish. A full session queue dropped events (the
                // bus marked this session) and the burst may have ENDED
                // there — no later seq will ever arrive to make the gap
                // observable, so the client would hold stale state
                // indefinitely. The drop necessarily left events queued
                // (the queue was full when it happened), so this check runs
                // after forwarding one of them: clear the mark ATOMICALLY
                // (one marker per observed episode) and send the reserved
                // resync marker straight down the writer channel — the bus
                // queue may still be full, so the marker must bypass it.
                // The send blocks under the writer's own backpressure,
                // exactly like a real event, and the marker rides the
                // existing Event wire shape, so every client parses it.
                // (R9-2: events and the marker reserve window slots — they
                // occupy the same memory the window exists to bound — but
                // the forwarder never WAITS on the window; see
                // MAX_UNWRITTEN_MESSAGES.)
                if overflowed.swap(false, Ordering::SeqCst)
                    && forward_window
                        .send_through(&forward_tx, resync_marker())
                        .is_err()
                {
                    break;
                }
            }
        })
    };

    let result = serve_messages(
        &mut read_half,
        SessionOutputs {
            writer_tx: writer_tx.clone(),
            gate_tx,
            window,
        },
        &handler,
        &peer,
        &stop,
        hello_deadline,
    );
    // Teardown order is load-bearing: dropping our sender alone is not
    // enough — the forwarder holds a clone — so we must unsubscribe BEFORE
    // joining. Unsubscribe closes the bus sender, which ends the forwarder,
    // which drops the last writer-sender clone, which ends the writer.
    // `gate_tx` is already gone by then: serve_messages took it by value,
    // so every one of its exit paths (including pre-hello refusals and
    // read errors) dropped it and unblocked the forwarder first. Joining
    // first deadlocks and leaks the session slot plus both threads
    // (rust-review finding 1).
    drop(writer_tx);
    drop(_guard);
    let _ = writer.join();
    let _ = event_forward.join();
    debug!(uid = peer.uid, outcome = ?result, "session closed");
}

/// Handshake + request loop for one session.
///
/// `outputs` carries the session's emit surface, taken BY VALUE so every
/// exit path drops `gate_tx` — the writer channel is FIFO, the ack is
/// queued before the gate's `()` is sent, and a session that never
/// handshook ends a forwarder still waiting on the gate (pr-champion
/// WO-5). Its window is the R9-2 request-credit window: the loop stops
/// READING requests while [`MAX_UNWRITTEN_MESSAGES`] messages remain
/// unwritten (see the const's arithmetic), and a parked loop leaves
/// through the writer's exit note or the stop flag — never a failed
/// send, because a parked loop is not sending.
fn serve_messages(
    read_half: &mut UnixStream,
    outputs: SessionOutputs,
    handler: &Arc<impl RequestHandler>,
    peer: &PeerCredentials,
    stop: &AtomicBool,
    hello_deadline: Duration,
) -> Result<(), FrameError> {
    let SessionOutputs {
        writer_tx,
        gate_tx,
        window,
    } = outputs;
    let mut reader = FrameReader::new(read_half);
    let connected_at = Instant::now();
    let mut hello_done = false;
    let mut client_info = None;
    while !stop.load(Ordering::SeqCst) {
        if !hello_done && connected_at.elapsed() > hello_deadline {
            let _ = writer_tx.send(ServerMessage::HelloError(HelloError {
                supported_version: PROTOCOL_VERSION,
                reason: "hello-timeout".into(),
            }));
            return Ok(());
        }
        // R9-2: the request-credit window. While K responses (or events)
        // remain unwritten, reading another request would only park more
        // client-amplified output: the loop pauses INSTEAD of reading, so
        // a pipelining client beyond the window waits rather than
        // buffers. Exit paths from the pause: the window reopens (the
        // writer put messages on the wire), the stop flag (checked at the
        // loop top after `continue`), or the writer's death — a parked
        // loop never sends, so only the window's exit note can tell it
        // the session is over.
        if hello_done && window.is_exhausted() {
            if window.writer_is_gone() {
                return Ok(());
            }
            std::thread::sleep(WRITE_WINDOW_POLL);
            continue;
        }
        // Codex PR review round 2, finding 2: the deadline must hold DURING
        // a frame too. A peer trickling one byte per sub-READ_POLL interval
        // keeps every individual read succeeding, so the loop above is not
        // revisited until the frame completes — a dribbled hello could hold
        // its reserved session slot indefinitely. The codec-level deadline
        // fails the read with TimedOut, which the arm below treats as
        // pollable; the check at the top of the loop then issues the
        // hello-timeout refusal. Post-hello reads are unbounded: a live
        // session may take as long as its client needs between requests.
        let message = match if hello_done {
            reader.read_msg::<ClientMessage>()
        } else {
            reader.read_msg_within::<ClientMessage>(connected_at + hello_deadline)
        } {
            Ok(m) => m,
            Err(FrameError::Io(e))
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        match message {
            ClientMessage::Hello {
                protocol_version,
                client,
            } => {
                if hello_done {
                    let _ = writer_tx.send(ServerMessage::HelloError(HelloError {
                        supported_version: PROTOCOL_VERSION,
                        reason: "duplicate-hello".into(),
                    }));
                    return Ok(());
                }
                if protocol_version > PROTOCOL_VERSION || protocol_version < 1 {
                    let _ = writer_tx.send(ServerMessage::HelloError(HelloError {
                        supported_version: PROTOCOL_VERSION,
                        reason: "unsupported-protocol-version".into(),
                    }));
                    return Ok(());
                }
                let client = client.sanitized();
                info!(uid = peer.uid, name = %client.name, "client connected");
                if window
                    .send_through(
                        &writer_tx,
                        ServerMessage::HelloAck(HelloAck {
                            // Speak the highest version both sides support.
                            protocol_version: protocol_version.min(PROTOCOL_VERSION),
                            daemon_version: handler.daemon_version().to_owned(),
                            latest_event_seq: handler.latest_event_seq(),
                        }),
                    )
                    .is_err()
                {
                    // The writer is gone; a client waiting on the ack would
                    // otherwise hang until its own timeout (rust-review
                    // finding 11).
                    return Ok(());
                }
                // The ack is queued ahead of anything the gated forwarder
                // holds, and the writer drains its channel in FIFO order —
                // so the ack is the first frame the client reads. Open the
                // gate; buffered pre-hello events follow the ack onto the
                // wire instead of beating it (pr-champion WO-5).
                let _ = gate_tx.send(());
                client_info = Some(client);
                hello_done = true;
            }
            ClientMessage::Request { id, request } => {
                let Some(client) = client_info.as_ref() else {
                    let _ = writer_tx.send(ServerMessage::HelloError(HelloError {
                        supported_version: PROTOCOL_VERSION,
                        reason: "request-before-hello".into(),
                    }));
                    return Ok(());
                };
                let ctx = SessionContext {
                    peer: *peer,
                    client: client.clone(),
                };
                let response = match dispatch(handler, &ctx, request) {
                    Ok(result) => Response::Ok { id, result },
                    Err(error) => Response::Error { id, error },
                };
                if window
                    .send_through(&writer_tx, ServerMessage::Response(response))
                    .is_err()
                {
                    return Ok(()); // writer is gone; nothing more to do
                }
            }
        }
    }
    Ok(())
}

/// The R9-2 request-credit window for one session: how many messages sit
/// queued on the session's writer channel but are not yet on the wire,
/// plus the writer thread's liveness note.
///
/// Every send into the writer channel reserves one slot BEFORE the
/// message is queued — the writer can never release a slot the senders
/// have not counted, so the counter cannot underflow — and the writer
/// releases it only after the message is fully on the wire. The
/// dispatcher stops READING new requests while [`MAX_UNWRITTEN_MESSAGES`]
/// slots are held, which bounds parked response bytes by construction
/// (the const's doc carries the arithmetic).
///
/// `writer_gone` is the window's liveness escape: a dispatcher parked on
/// the window is not sending, so it cannot learn of the writer's death
/// from a failed send — the writer notes its exit BEFORE its channel
/// receiver drops, and the parked dispatcher polls that note.
#[derive(Debug, Default)]
struct WriteWindow {
    /// Messages queued on the writer channel but not yet on the wire.
    unwritten: AtomicUsize,
    /// Set by the writer thread just before its channel receiver drops.
    writer_gone: AtomicBool,
}

impl WriteWindow {
    /// A window with nothing parked and a live writer.
    fn new() -> Self {
        Self::default()
    }

    /// Reserves one slot for a message about to be queued.
    fn reserve(&self) {
        self.unwritten.fetch_add(1, Ordering::SeqCst);
    }

    /// Releases one slot after its message reached the wire.
    ///
    /// EXCEPTION (sec-auditor round-9 verdict, R9-2 Low): the four
    /// hello-error refusals are UNRESERVED terminal sends — the session
    /// is ending and must not wait on the window — yet the writer still
    /// releases them, so `unwritten` wraps below zero on those paths.
    /// Benign by construction: the wrap only occurs on session-ending
    /// refusals, after which no request is ever read again and the
    /// counter's meaning ends with the session (is_exhausted compares
    /// against the ceiling; a negative value is never "full"). Routing
    /// the refusals through reserve would add a window wait to a path
    /// whose whole point is to end NOW — the exception is deliberate.
    fn release(&self) {
        self.unwritten.fetch_sub(1, Ordering::SeqCst);
    }

    /// Whether the dispatcher must pause request reads: the window is
    /// full of unwritten output.
    fn is_exhausted(&self) -> bool {
        self.unwritten.load(Ordering::SeqCst) >= MAX_UNWRITTEN_MESSAGES
    }

    /// Whether the writer thread has exited (a parked dispatcher's only
    /// exit beside the stop flag).
    fn writer_is_gone(&self) -> bool {
        self.writer_gone.load(Ordering::SeqCst)
    }

    /// The writer's exit note — stored before its channel receiver drops
    /// (see the struct doc).
    fn note_writer_exit(&self) {
        self.writer_gone.store(true, Ordering::SeqCst);
    }

    /// Queues `message` on `tx`, first reserving its window slot.
    ///
    /// A failed send leaks the reservation deliberately — a failed send
    /// means the writer channel's receiver is gone, so the session is
    /// ending and the window will never be consulted again.
    fn send_through(
        &self,
        tx: &mpsc::SyncSender<ServerMessage>,
        message: ServerMessage,
    ) -> Result<(), mpsc::SendError<ServerMessage>> {
        self.reserve();
        tx.send(message)
    }
}

/// The session's emit surface, handed to [`serve_messages`] BY VALUE:
/// dropping `gate_tx` on every exit path is what ends a forwarder still
/// waiting on the hello gate, and the writer sender clone gives the loop
/// its queue handle while `handle_session` keeps its own for teardown.
/// The window is the R9-2 bound both senders share with the writer.
struct SessionOutputs {
    /// The dispatcher's clone of the session writer channel.
    writer_tx: mpsc::SyncSender<ServerMessage>,
    /// Opens the event gate after the hello ack is queued.
    gate_tx: mpsc::SyncSender<()>,
    /// The shared request-credit window (R9-2).
    window: Arc<WriteWindow>,
}

/// Authorization plus handler execution for one request.
fn dispatch(
    handler: &Arc<impl RequestHandler>,
    ctx: &SessionContext,
    request: Request,
) -> Result<RequestResult, RpcError> {
    authorize(required_role(&request), &ctx.peer)?;
    handler.handle(ctx, request)
}

#[cfg(test)]
mod tests {
    use protonwire_frontend_api::Request;

    use super::*;
    use crate::frame::{read_msg, write_msg};
    use crate::server::test_support::{
        NullHandler, connect_and_hello, info, set_rcvbuf, spawn_server,
    };
    use crate::server::{IpcServer, ServeBudgets};

    /// Regression (rust-review finding 1): every ended session must
    /// release its bus slot and session threads. The pre-fix teardown
    /// joined the writer before unsubscribing, deadlocking on the
    /// forwarder's sender clone — leaking a slot and two threads per
    /// session until MAX_SESSIONS wedged the daemon permanently.
    #[test]
    fn ended_sessions_release_their_bus_slot() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, Arc::clone(&handler));
        let path = server.socket_path().to_owned();

        for _ in 0..8 {
            drop(connect_and_hello(&path));
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        while handler.event_bus().session_count() != 0 {
            assert!(
                Instant::now() < deadline,
                "sessions leaked: {} slot(s) still subscribed after all clients \
                 disconnected — teardown is deadlocked again",
                handler.event_bus().session_count()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while handler.event_bus().active_sessions() != 0 {
            assert!(
                Instant::now() < deadline,
                "session slots leaked: {} still reserved after all clients \
                 disconnected",
                handler.event_bus().active_sessions()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Finding 10: the handshake must reject versions below the oldest
    /// supported protocol (1), not ack them into a lie.
    #[test]
    fn hello_below_oldest_supported_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, handler);
        let mut stream = std::os::unix::net::UnixStream::connect(server.socket_path()).unwrap();
        write_msg(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: 0,
                client: info(),
            },
        )
        .unwrap();
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloError(err) => {
                assert_eq!(err.reason, "unsupported-protocol-version");
                assert_eq!(err.supported_version, 1);
            }
            other => panic!("expected HelloError for version 0, got {other:?}"),
        }
    }

    /// Characterization (refactorer step 2): the handshake refusals that
    /// M2's protocol-negotiation work will edit around. Each pins the
    /// exact wire behavior of `serve_messages` through the public socket.
    #[test]
    fn hello_above_ceiling_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, handler);
        let mut stream = std::os::unix::net::UnixStream::connect(server.socket_path()).unwrap();
        write_msg(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: 99,
                client: info(),
            },
        )
        .unwrap();
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloError(err) => {
                assert_eq!(err.reason, "unsupported-protocol-version");
                assert_eq!(err.supported_version, PROTOCOL_VERSION);
            }
            other => panic!("expected HelloError for version 99, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_hello_is_refused_and_disconnected() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, handler);
        let mut stream = connect_and_hello(server.socket_path());
        write_msg(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: 1,
                client: info(),
            },
        )
        .unwrap();
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloError(err) => assert_eq!(err.reason, "duplicate-hello"),
            other => panic!("expected HelloError for duplicate hello, got {other:?}"),
        }
        // The session ends: the next read hits EOF.
        assert!(matches!(
            read_msg::<_, ServerMessage>(&mut stream),
            Err(crate::frame::FrameError::Truncated)
        ));
    }

    #[test]
    fn request_before_hello_is_refused_and_disconnected() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, handler);
        let mut stream = std::os::unix::net::UnixStream::connect(server.socket_path()).unwrap();
        write_msg(
            &mut stream,
            &ClientMessage::Request {
                id: 1,
                request: Request::GetState,
            },
        )
        .unwrap();
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloError(err) => assert_eq!(err.reason, "request-before-hello"),
            other => panic!("expected HelloError for early request, got {other:?}"),
        }
        assert!(matches!(
            read_msg::<_, ServerMessage>(&mut stream),
            Err(crate::frame::FrameError::Truncated)
        ));
    }

    #[test]
    fn negotiated_version_is_min_of_client_and_server() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, handler);
        let mut stream = std::os::unix::net::UnixStream::connect(server.socket_path()).unwrap();
        write_msg(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: 1,
                client: info(),
            },
        )
        .unwrap();
        // A client at the oldest supported version negotiates exactly it;
        // when PROTOCOL_VERSION grows, offering 1 must still ack 1.
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloAck(ack) => assert_eq!(ack.protocol_version, 1),
            other => panic!("expected HelloAck, got {other:?}"),
        }
    }

    /// Codex PR review finding 5 (P2; tracked as rust-review #12): a peer
    /// that writes part of a frame, pauses longer than the 250 ms read
    /// poll, then writes the rest must NOT desynchronize the session. The
    /// pre-fix stateless read discarded the partial bytes on WouldBlock
    /// and re-read the remainder as a fresh length prefix.
    #[test]
    fn partial_frame_across_read_timeouts_stays_synchronized() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, handler);
        let mut stream = std::os::unix::net::UnixStream::connect(server.socket_path()).unwrap();

        // Serialize the hello frame, deliver 3 prefix bytes, stall past
        // READ_POLL, then the rest.
        let mut frame = Vec::new();
        write_msg(
            &mut frame,
            &ClientMessage::Hello {
                protocol_version: 1,
                client: info(),
            },
        )
        .unwrap();
        assert!(frame.len() > 8);
        stream.write_all(&frame[..3]).unwrap();
        stream.flush().unwrap();
        std::thread::sleep(READ_POLL * 3);
        stream.write_all(&frame[3..]).unwrap();
        stream.flush().unwrap();

        // The session must still parse the hello and answer the ack.
        match read_msg::<_, ServerMessage>(&mut stream) {
            Ok(ServerMessage::HelloAck(_)) => {}
            other => panic!("expected HelloAck after a split frame, got {other:?}"),
        }
        // ...and stay synchronized for a follow-up exchange.
        write_msg(
            &mut stream,
            &ClientMessage::Request {
                id: 7,
                request: Request::GetState,
            },
        )
        .unwrap();
        match read_msg::<_, ServerMessage>(&mut stream) {
            Ok(ServerMessage::Response(response)) => assert_eq!(response.id(), 7),
            other => panic!("expected a correlated response, got {other:?}"),
        }
    }

    /// Codex PR review round 2, finding 2 (P2): HELLO_DEADLINE was only
    /// re-checked between COMPLETE frames. A peer that supplies one byte
    /// before each 250 ms read timeout keeps `FrameReader`'s inner fill
    /// loop satisfied — no error ever surfaces — so a maximum-sized hello
    /// could dribble for hours while holding a reserved session slot.
    /// The hello-phase read must fail once the deadline passes even while
    /// bytes keep arriving.
    ///
    /// QA robustness (consolidated round 3, item H): the deadline is
    /// injected at 500 ms and the dribble runs 25 ms/byte — the same
    /// behavioral claim at a tenth of the wall clock and far more tolerant
    /// of a loaded test machine (the margin between the dribble pace and
    /// the deadline is what the assertion needs, not absolute seconds).
    #[test]
    fn hello_deadline_holds_against_a_steady_byte_dribble() {
        use std::io::Write;
        use std::time::{Duration, Instant};

        const DRIBBLE_MS_PER_BYTE: u64 = 25;
        let hello_deadline = Duration::from_millis(500);

        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let server = IpcServer::bind(dir.path(), "dribble.sock").unwrap();
        let stop_flag = Arc::clone(&stop);
        std::thread::spawn(move || {
            server.serve_with(
                handler,
                stop_flag,
                ServeBudgets {
                    hello_deadline,
                    ..ServeBudgets::default()
                },
            )
        });
        let stream =
            std::os::unix::net::UnixStream::connect(dir.path().join("dribble.sock")).unwrap();
        let mut read_half = stream.try_clone().unwrap();
        let mut write_half = stream;

        let mut frame = Vec::new();
        write_msg(
            &mut frame,
            &ClientMessage::Hello {
                protocol_version: 1,
                client: info(),
            },
        )
        .unwrap();
        // The dribble would complete this frame in well over double the
        // deadline, and no single read ever hits the 250 ms poll timeout —
        // the exact shape of the claimed dribble.
        assert!(
            frame.len() as u64 * DRIBBLE_MS_PER_BYTE > hello_deadline.as_millis() as u64 * 2,
            "fixture frame must out-dribble the deadline"
        );

        let dribbler = std::thread::spawn(move || {
            for byte in frame {
                if write_half.write_all(&[byte]).is_err() {
                    break; // the server hung up mid-dribble
                }
                let _ = write_half.flush();
                std::thread::sleep(Duration::from_millis(DRIBBLE_MS_PER_BYTE));
            }
        });

        read_half
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let started = Instant::now();
        match read_msg::<_, ServerMessage>(&mut read_half) {
            Ok(ServerMessage::HelloError(err)) => {
                assert_eq!(err.reason, "hello-timeout");
                assert!(
                    started.elapsed() < hello_deadline + Duration::from_secs(1),
                    "refusal arrived well past the deadline"
                );
            }
            other => panic!("expected a hello-timeout refusal, got {other:?}"),
        }
        // The session ends after the refusal.
        assert!(matches!(
            read_msg::<_, ServerMessage>(&mut read_half),
            Err(crate::frame::FrameError::Truncated)
        ));
        dribbler.join().unwrap();
        stop.store(true, Ordering::SeqCst);
    }

    /// pr-champion WO-5: `subscribe()` and the forwarder spawn preceded the
    /// hello exchange, so an event published in that window reached the
    /// wire before `HelloAck` — and a client rejects anything but the ack
    /// while handshaking ("unexpected message during handshake",
    /// client.rs). The ack must be the first frame on the wire; the
    /// buffered event follows it.
    ///
    /// WO-R4 hardening, both directions:
    /// - GREEN-side regressions used to present as INFINITE HANGS (the
    ///   test stream had no read timeout), so the stream now carries a
    ///   5 s one and the ack's arrival is asserted punctual — a broken
    ///   gate fails fast instead of hanging the suite.
    /// - The red side used to rely on a 100 ms sleep heuristic. It is now
    ///   a DETERMINISTIC readability poll (nix::poll POLLIN, 750 ms)
    ///   between publishing the pre-hello event and sending Hello:
    ///   readable means an event frame is ALREADY on the wire pre-hello —
    ///   read it and fail reporting that frame; timeout means the gate
    ///   held it — proceed to Hello and assert ack-first (no sleep on
    ///   the green path).
    #[test]
    fn hello_ack_is_the_first_frame_even_under_pre_hello_events() {
        use nix::poll::{PollFd, PollFlags, poll as poll_fd};
        use protonwire_frontend_api::{Event, EventEnvelope, NoticeLevel};
        use std::os::fd::AsFd;

        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, Arc::clone(&handler));
        let mut stream = std::os::unix::net::UnixStream::connect(server.socket_path()).unwrap();
        // No-hang gate: every read below is bounded, so a regression that
        // stops the ack (or the follow-up event) surfaces as a fast TimedOut
        // failure rather than a suite-wide hang.
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Wait until the session has actually subscribed: the accept loop
        // polls at 250 ms, so a fixed sleep can race the subscribe and a
        // too-early publish would miss the session entirely.
        let deadline = Instant::now() + Duration::from_secs(10);
        while handler.event_bus().session_count() != 1 {
            assert!(Instant::now() < deadline, "session never subscribed");
            std::thread::sleep(Duration::from_millis(5));
        }

        // Publish BEFORE the hello, then poll the wire — deterministically,
        // not with a sleep. If the gate is broken the event is already on
        // the socket and POLLIN fires within the poll window; if the gate
        // held it, nothing is readable and the poll times out.
        handler
            .event_bus()
            .publish(ServerMessage::Event(EventEnvelope {
                seq: 1,
                event: Event::Notice {
                    level: NoticeLevel::Info,
                    message: "pre-hello".into(),
                },
            }));
        let mut fds = [PollFd::new(stream.as_fd(), PollFlags::POLLIN)];
        let readable = poll_fd(&mut fds, 750u16).unwrap() > 0
            && fds[0]
                .revents()
                .unwrap_or(PollFlags::empty())
                .contains(PollFlags::POLLIN);
        if readable {
            // Deterministic red: an event frame beat the handshake onto
            // the wire. Read and REPORT it instead of proceeding into a
            // misleading downstream assertion.
            let leaked: ServerMessage = read_msg(&mut stream).unwrap();
            match &leaked {
                ServerMessage::Event(_) => panic!(
                    "the event gate leaked: an event frame reached the wire \
                     before Hello — got {leaked:?}"
                ),
                // Any other frame (a HelloError, say) is a different
                // handshake defect, not an event-gate leak — say so
                // instead of misattributing it (rust-review Low).
                other => panic!(
                    "a non-event frame reached the wire before Hello — not an \
                     event-gate leak but a different handshake defect: got {other:?}"
                ),
            }
        }

        // The gate held the event: send Hello and demand the ack first,
        // promptly.
        let hello_sent_at = Instant::now();
        write_msg(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: 1,
                client: info(),
            },
        )
        .unwrap();
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloAck(_) => {}
            other => panic!("hello ack must be the first frame, got {other:?}"),
        }
        assert!(
            hello_sent_at.elapsed() < Duration::from_secs(5),
            "the ack must arrive punctually, took {} ms — a regression is \
             dragging the handshake",
            hello_sent_at.elapsed().as_millis()
        );
        // The buffered event is delivered right after the ack, not ahead
        // of it.
        match read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::Event(envelope) => assert_eq!(envelope.seq, 1),
            other => panic!("expected the buffered event after the ack, got {other:?}"),
        }
    }

    /// X4 (round 8), wire-level pin: a burst that overflows the session
    /// queue and ENDS there must still produce the reserved resync marker
    /// on the wire — without any further publish. The raw socket below
    /// never reads during the burst (so the queue provably fills and the
    /// tail is dropped), then drains under a bounded watchdog until the
    /// marker frame arrives.
    #[test]
    fn end_of_burst_overflow_emits_the_reserved_resync_marker() {
        use crate::frame::FrameReader;

        // 32 KiB payloads so the burst cannot hide in the socket send
        // buffer: a few frames there + writer channel (256) + session
        // queue (256) cannot hold 1024 events, so the tail is dropped.
        const PAYLOAD: usize = 32 * 1024;
        const BURST: u64 = 1024;

        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(NullHandler {
            version: "test".into(),
            bus: EventBus::new(),
        });
        let server = spawn_server(&dir, Arc::clone(&handler));
        let stream = connect_and_hello(server.socket_path());
        // Short poll between frames; the FrameReader below keeps partial
        // state, so a mid-frame expiry resumes instead of desynchronizing.
        stream
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let mut reader = FrameReader::new(stream);

        // Wait for the subscription to exist (the accept loop polls at
        // 250 ms), then burst without reading.
        let deadline = Instant::now() + Duration::from_secs(10);
        while handler.event_bus().session_count() != 1 {
            assert!(Instant::now() < deadline, "session never subscribed");
            std::thread::sleep(Duration::from_millis(5));
        }
        let notice = "x".repeat(PAYLOAD);
        for seq in 1..=BURST {
            handler
                .event_bus()
                .publish(ServerMessage::Event(EventEnvelope {
                    seq,
                    event: Event::Notice {
                        level: NoticeLevel::Info,
                        message: notice.clone(),
                    },
                }));
        }
        // The burst ENDS here: nothing further is published below.

        let deadline = Instant::now() + Duration::from_secs(20);
        let mut events = 0u64;
        let mut marker = false;
        while !marker {
            assert!(
                Instant::now() < deadline,
                "the reserved resync marker never reached the wire: {events} \
                 events drained, then silence — the end-of-burst drop is \
                 invisible without a later publish (X4)"
            );
            match reader.read_msg::<ServerMessage>() {
                Ok(ServerMessage::Event(envelope)) if envelope.seq == EVENT_SEQ_RESYNC_NOW => {
                    marker = true
                }
                Ok(ServerMessage::Event(_)) => events += 1,
                Err(FrameError::Io(e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue; // nothing readable yet; re-poll the watchdog
                }
                other => panic!("unexpected frame while draining: {other:?}"),
            }
        }
        assert!(
            events < BURST,
            "the tail was dropped, so fewer than the whole burst can have \
             been delivered before the marker; saw {events}"
        );
        assert_eq!(
            handler.event_bus().session_count(),
            1,
            "retain-on-Full: the overflowed session must stay subscribed"
        );
    }

    /// Codex round 5 (P1): the writer thread exiting on a write timeout
    /// left the session alive — the dispatcher's read half (a try_clone of
    /// the SAME socket) kept polling unbounded post-hello, so a client that
    /// triggers the 10 s write ceiling with an oversized response and then
    /// holds its side open kept its reserved session slot forever; 64 such
    /// connections permanently wedged the daemon at MAX_SESSIONS. The
    /// writer must take the session with it: shutting the shared socket
    /// down fails the dispatcher's read and drives the normal teardown
    /// (unsubscribe + slot release).
    #[test]
    fn writer_failure_tears_down_the_session() {
        /// Answers pings with a 2 MiB pong — beyond MAX_FRAME_LEN, so the
        /// writer's write_msg fails the moment it dequeues the response.
        struct HugePong {
            bus: Arc<EventBus>,
        }
        impl RequestHandler for HugePong {
            fn daemon_version(&self) -> &str {
                "test"
            }
            fn latest_event_seq(&self) -> u64 {
                0
            }
            fn handle(
                &self,
                _ctx: &SessionContext,
                request: Request,
            ) -> Result<RequestResult, RpcError> {
                match request {
                    // Oversized ON PURPOSE: a response payload beyond
                    // MAX_FRAME_LEN makes write_msg fail inside the writer
                    // thread immediately — a writer failure with no
                    // dependence on host SO_SNDTIMEO behavior (see the
                    // comment at the trigger below).
                    Request::Ping { .. } => Ok(RequestResult::Pong {
                        nonce: "x".repeat(2 * crate::frame::MAX_FRAME_LEN),
                    }),
                    _ => Err(RpcError::new(
                        protonwire_frontend_api::RpcErrorCode::NotImplemented,
                        "test handler",
                    )),
                }
            }
            fn event_bus(&self) -> &EventBus {
                &self.bus
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(HugePong {
            bus: Arc::new(EventBus::new()),
        });
        let server = IpcServer::bind(dir.path(), "writer-fail.sock").unwrap();
        let path = server.socket_path().to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let served = {
            let handler = Arc::clone(&handler);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || server.serve(handler, stop))
        };

        let mut stream = connect_and_hello(&path);
        // A tiny request (the oversized half is the RESPONSE): the server
        // dispatches it, the writer dequeues the 2 MiB pong, and write_msg
        // rejects it as TooLarge — a writer failure that fires on every
        // host. (The review finding's literal trigger — a blocked write
        // dying at the 10 s SO_SNDTIMEO ceiling — does NOT fire on this
        // kernel: instrumented runs show a blocked AF_UNIX send to a
        // 4 KiB peer buffer outlasting a 20 s window with a 10 s write
        // timeout set. The teardown invariant is trigger-agnostic, so it
        // is pinned with the deterministic failure; the kernel-dependent
        // timeout flavor is flagged in docs/review-log.md.)
        write_msg(
            &mut stream,
            &ClientMessage::Request {
                id: 1,
                request: Request::Ping {
                    nonce: "ping".into(),
                },
            },
        )
        .unwrap();

        // The client never reads and NEVER closes (`stream` stays alive):
        // pre-fix the writer exited on the failed write and nothing else
        // happened — the reserved slot stayed while the dispatcher polled
        // its open read half forever. The session must instead tear down
        // promptly after the writer's failure.
        let deadline = Instant::now() + Duration::from_secs(10);
        while handler.event_bus().active_sessions() != 0 {
            assert!(
                Instant::now() < deadline,
                "the session outlived its failed writer — a held-open client \
                 keeps its reserved slot after the writer died"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // The subscription went away too (the teardown guards ran).
        let deadline = Instant::now() + Duration::from_secs(5);
        while handler.event_bus().session_count() != 0 {
            assert!(
                Instant::now() < deadline,
                "subscription leaked after the writer-failure teardown"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // FU-3 (rust-review round-5 follow-up, Low): the assertions above
        // observe only SERVER-side counters — the client-visible half of
        // the 842c0c1 contract ("the writer takes the session down AND
        // the client learns of it") was pinned by nothing. A bounded read
        // must observe EOF: it fails whenever the teardown completes on
        // the server side while the socket (or its write half) stays
        // alive anywhere else — e.g. a weakened shutdown paired with a
        // strong reference that outlives the session (the exact class
        // the Weak SessionWorker handle exists to prevent). A client
        // blocked reading its response would otherwise hang forever.
        use std::io::Read;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0u8; 1];
        // `== Ok(0)` in assert form: any Err (a read timeout above all —
        // the Shutdown::Read mutation's signature) fails the expect; a
        // successful read must be the 0-byte EOF.
        assert_eq!(
            stream
                .read(&mut byte)
                .expect("the client's read must answer within the timeout"),
            0,
            "the failed writer must deliver EOF to its client — a client \
             blocked reading its response would hang forever"
        );
        stop.store(true, Ordering::SeqCst);
        let _ = served.join();
    }

    /// Answers pings with a ~0.86 MiB pong — a VALID frame (under
    /// MAX_FRAME_LEN, so it actually goes on the wire, unlike the TooLarge
    /// fixture in `writer_failure_tears_down_the_session`) sized to
    /// overwhelm any peer that is not reading fast enough. Shared by the
    /// R7-1 watchdog scenarios.
    struct HugeValidPong {
        bus: Arc<EventBus>,
    }
    impl RequestHandler for HugeValidPong {
        fn daemon_version(&self) -> &str {
            "test"
        }
        fn latest_event_seq(&self) -> u64 {
            0
        }
        fn handle(
            &self,
            _ctx: &SessionContext,
            request: Request,
        ) -> Result<RequestResult, RpcError> {
            match request {
                Request::Ping { .. } => Ok(RequestResult::Pong {
                    nonce: "x".repeat(900_000),
                }),
                _ => Err(RpcError::new(
                    protonwire_frontend_api::RpcErrorCode::NotImplemented,
                    "test handler",
                )),
            }
        }
        fn event_bus(&self) -> &EventBus {
            &self.bus
        }
    }

    /// R7-1 (round-5 track item, escalated P1): the writer thread's writes
    /// must be deadline-bounded in USERSPACE, because `SO_SNDTIMEO` is a
    /// per-WAIT bound, not a message bound: round-5's instrumented run
    /// watched a ~0.9 MiB send to a 4 KiB-rcvbuf peer that never reads
    /// "outlast 20 s under a 10 s timeout", and the round-7 sec probe
    /// measured the two defects directly — progress resets the wait, and
    /// a multi-syscall write multiplies it (a 0.9 MiB frame is ~4
    /// syscalls), while a steadily draining peer keeps it resetting
    /// indefinitely (80+ s under a 1 s timeout). A writer that never
    /// exits means
    /// the round-5 V1 teardown (writer exit ⇒ shared-socket shutdown ⇒
    /// slot release) never fires: a client that merely holds its side
    /// open keeps its reserved session slot far past the ceiling — 64
    /// such connections wedge the daemon at MAX_SESSIONS.
    ///
    /// The trigger is the literal finding: a VALID ~0.86 MiB pong (under
    /// MAX_FRAME_LEN, unlike the TooLarge fixture above, which never
    /// reaches the wire), a 4 KiB `SO_RCVBUF`, and a client that never
    /// reads and never closes. The write ceiling is shrunk through
    /// [`ServeBudgets`] (the ServeBudgets pattern: `WRITE_TIMEOUT` becomes
    /// injectable so the watchdog scenario runs in seconds instead of a
    /// 20 s wall-clock red; production keeps the 10 s default). The red
    /// is the WALL-CLOCK separation: the red run below shows the slot
    /// still held 3007 ms into a 2000 ms ceiling when the watchdog
    /// assert fired (per-syscall waits stretching past the ceiling);
    /// post-fix the userspace deadline tears the session down at ~1x.
    #[test]
    fn blocked_writer_releases_its_session_at_the_write_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(HugeValidPong {
            bus: Arc::new(EventBus::new()),
        });
        let server = IpcServer::bind(dir.path(), "writer-watchdog.sock").unwrap();
        let path = server.socket_path().to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let write_ceiling = Duration::from_secs(2);
        let served = {
            let handler = Arc::clone(&handler);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                server.serve_with(
                    handler,
                    stop,
                    ServeBudgets {
                        write_timeout: write_ceiling,
                        ..ServeBudgets::default()
                    },
                )
            })
        };

        // Handshake, shrink the receive buffer, request the huge pong, and
        // NEVER read (and never close): the writer's frame cannot fit and
        // the write stalls mid-payload.
        let mut stream = connect_and_hello(&path);
        set_rcvbuf(&stream, 4096);
        write_msg(
            &mut stream,
            &ClientMessage::Request {
                id: 1,
                request: Request::Ping {
                    nonce: "ping".into(),
                },
            },
        )
        .unwrap();

        // Wall-clock watchdog: the reserved slot must be back inside the
        // ceiling plus scheduling slack. Pre-fix — the writer blocked
        // inside write_all, with no whole-message bound to end it — the
        // slot was still held at 3007 ms of a 2000 ms ceiling when the
        // assert fired (the red run's evidence).
        let started = Instant::now();
        while handler.event_bus().active_sessions() != 0 {
            assert!(
                Instant::now() < started + write_ceiling + Duration::from_secs(1),
                "the session outlived its write deadline — the slot is still \
                 held {} ms into a {} ms ceiling: a blocked writer pins the \
                 daemon one MAX_SESSIONS wedge at a time",
                started.elapsed().as_millis(),
                write_ceiling.as_millis()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        // The subscription tore down with the slot.
        let deadline = Instant::now() + Duration::from_secs(5);
        while handler.event_bus().session_count() != 0 {
            assert!(
                Instant::now() < deadline,
                "subscription leaked after the write-deadline teardown"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            started.elapsed() < write_ceiling + Duration::from_secs(1),
            "the write-deadline teardown overran: {} ms for a {} ms ceiling",
            started.elapsed().as_millis(),
            write_ceiling.as_millis()
        );
        stop.store(true, Ordering::SeqCst);
        let _ = served.join();
    }

    /// R7-1's partial-progress companion — the write-side mirror of the
    /// round-2 dribbled-READ finding. A peer that keeps freeing a LITTLE
    /// space should, on textbook semantics, keep every write succeeding
    /// with partial progress, stretching one ~0.86 MiB frame across the
    /// peer's whole drain rate (4 KiB per 150 ms ≈ 34 s here) while the
    /// reserved slot sits held — no per-syscall ceiling can bound that.
    /// (The sec round-7 probe measured this directly: 80+ s of dribble
    /// progress under a 1 s timeout — every freed byte resets the wait,
    /// so the syscall ceiling never fires at all.) Only a WHOLE-MESSAGE
    /// deadline bounds the frame:
    /// pre-fix the red run below shows the slot still held 3022 ms into a
    /// 2000 ms ceiling; post-fix the watchdog tears the session down at
    /// the ceiling. This variant is also the one with teeth against a
    /// reset-the-deadline-per-chunk mutation — a resetting deadline
    /// stretches to the drainer's ~34 s pace and fails the watchdog.
    #[test]
    fn slow_draining_peer_releases_the_session_at_the_write_deadline() {
        use std::io::Read;

        let dir = tempfile::tempdir().unwrap();
        let handler = Arc::new(HugeValidPong {
            bus: Arc::new(EventBus::new()),
        });
        let server = IpcServer::bind(dir.path(), "writer-dribble.sock").unwrap();
        let path = server.socket_path().to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let write_ceiling = Duration::from_secs(2);
        let served = {
            let handler = Arc::clone(&handler);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                server.serve_with(
                    handler,
                    stop,
                    ServeBudgets {
                        write_timeout: write_ceiling,
                        ..ServeBudgets::default()
                    },
                )
            })
        };

        // Handshake, shrink the receive buffer, and park a reader that
        // drains 4 KiB every 150 ms — a pace at which one ~0.86 MiB pong
        // takes ~34 s, far past any per-message ceiling, while the socket
        // keeps tripping "slightly writable".
        let mut stream = connect_and_hello(&path);
        set_rcvbuf(&stream, 4096);
        let hurry = Arc::new(AtomicBool::new(false));
        let hurry_flag = Arc::clone(&hurry);
        let mut drain_half = stream.try_clone().unwrap();
        let drainer = std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match drain_half.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if !hurry_flag.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_millis(150));
                        }
                    }
                }
            }
        });
        write_msg(
            &mut stream,
            &ClientMessage::Request {
                id: 1,
                request: Request::Ping {
                    nonce: "ping".into(),
                },
            },
        )
        .unwrap();

        // Wall-clock watchdog (the red): the slot must be back inside the
        // ceiling plus slack. Pre-fix the slot was still held at 3022 ms
        // of a 2000 ms ceiling when this assert fired — per-syscall waits
        // stretching at best, an unbounded dribble at worst.
        let started = Instant::now();
        while handler.event_bus().active_sessions() != 0 {
            assert!(
                Instant::now() < started + write_ceiling + Duration::from_secs(1),
                "the session outlived its write deadline — partial-progress \
                 writes pinned the writer: the slot is still held {} ms into \
                 a {} ms ceiling",
                started.elapsed().as_millis(),
                write_ceiling.as_millis()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while handler.event_bus().session_count() != 0 {
            assert!(
                Instant::now() < deadline,
                "subscription leaked after the write-deadline teardown"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            started.elapsed() < write_ceiling + Duration::from_secs(1),
            "the write-deadline teardown overran: {} ms for a {} ms ceiling",
            started.elapsed().as_millis(),
            write_ceiling.as_millis()
        );
        // Let the drainer finish quickly (drain the buffered remainder at
        // full speed until the teardown's EOF) and keep the socket alive
        // for exactly as long as the test needs it.
        hurry.store(true, Ordering::SeqCst);
        let _ = drainer.join();
        stop.store(true, Ordering::SeqCst);
        let _ = served.join();
    }

    /// R9-2 (round 9, P1 — the round's hardest): the session writer
    /// channel (sync_channel(256), shared by responses AND events) let a
    /// pipelining authorized client park ~230 MiB per session — ~14 GiB
    /// across MAX_SESSIONS — by stalling its reader: the dispatcher's
    /// send-blocking was backpressure on the dispatch THREAD, never a
    /// bound on parked BYTES, and the per-message write watchdog (R7-1)
    /// only ends an already-stuck write; it does nothing about the 256
    /// deserialized responses parked behind it. The fix is a
    /// request-credit window: the dispatcher stops READING new requests
    /// while K responses remain unwritten, so a burst past the window
    /// WAITS rather than buffers — memory bounded by construction, no
    /// termination semantics, a hostile client just experiences flow
    /// control.
    ///
    /// The memory proxy for the assert is the handler's dispatch count:
    /// every dispatched request becomes exactly one queued response, so
    /// "dispatches <= window + slack" is "parked responses <= window +
    /// slack". Pre-fix the count runs away to the full channel (the red
    /// run's evidence); post-fix it must stop inside the documented
    /// window. The write ceiling is shrunk through ServeBudgets (the
    /// established watchdog pattern) so the stalled writer dies in
    /// seconds and teardown is prompt.
    #[test]
    fn pipelined_burst_against_a_stalled_reader_parks_only_the_window() {
        use std::sync::atomic::AtomicUsize;

        // Near-max responses: a nonce just under MAX_FRAME_LEN makes each
        // Pong a ~0.9 MiB frame — the finding's per-message size.
        const NONCE: usize = 900_000;
        // More than the old 256-slot channel plus the blocked send, so
        // pre-fix the dispatcher provably runs past any window-sized
        // bound; the client never reads a byte of the responses.
        const BURST: u64 = 280;
        // The documented budget (R9-2): K unwritten messages per session,
        // straight from the production constant so test and doc cannot
        // drift. (The red run used a literal 16; the green binds it here.)
        const MAX_UNWRITTEN: usize = MAX_UNWRITTEN_MESSAGES;
        const SLACK: usize = 2; // one mid-dispatch, one mid-write

        struct CountingEchoPong {
            bus: Arc<EventBus>,
            dispatched: Arc<AtomicUsize>,
        }
        impl RequestHandler for CountingEchoPong {
            fn daemon_version(&self) -> &str {
                "test"
            }
            fn latest_event_seq(&self) -> u64 {
                0
            }
            fn handle(
                &self,
                _ctx: &SessionContext,
                request: Request,
            ) -> Result<RequestResult, RpcError> {
                match request {
                    Request::Ping { nonce } => {
                        self.dispatched.fetch_add(1, Ordering::SeqCst);
                        Ok(RequestResult::Pong { nonce })
                    }
                    _ => Err(RpcError::new(
                        protonwire_frontend_api::RpcErrorCode::NotImplemented,
                        "test handler",
                    )),
                }
            }
            fn event_bus(&self) -> &EventBus {
                &self.bus
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let dispatched = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(CountingEchoPong {
            bus: Arc::new(EventBus::new()),
            dispatched: Arc::clone(&dispatched),
        });
        let server = IpcServer::bind(dir.path(), "credit-window.sock").unwrap();
        let path = server.socket_path().to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let write_ceiling = Duration::from_secs(2);
        let served = {
            let handler = Arc::clone(&handler);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                server.serve_with(
                    handler,
                    stop,
                    ServeBudgets {
                        write_timeout: write_ceiling,
                        ..ServeBudgets::default()
                    },
                )
            })
        };

        // Handshake (so the ack is drained), then starve the receive path:
        // the writer's first ~0.9 MiB frame cannot fit a 4 KiB peer and
        // the session's output stops moving.
        let mut stream = connect_and_hello(&path);
        set_rcvbuf(&stream, 4096);

        // Pipeline the whole burst without ever reading a response. The
        // helper thread parks once the socket refuses more bytes — which
        // is exactly the point: pre-fix that happens only when the kernel
        // buffers saturate (hundreds of MiB already parked daemon-side),
        // post-fix when the window closes.
        let nonce = "x".repeat(NONCE);
        let pipeliner = std::thread::spawn(move || {
            for id in 1..=BURST {
                if write_msg(
                    &mut stream,
                    &ClientMessage::Request {
                        id,
                        request: Request::Ping {
                            nonce: nonce.clone(),
                        },
                    },
                )
                .is_err()
                {
                    break; // the session ended under us
                }
            }
        });

        // Watchdog: wait for the dispatch count to stabilize (unchanged
        // across a poll gap), then hold it to the window. Pre-fix the
        // count marches to the channel capacity — the red; post-fix it
        // stops at the window and the assert holds.
        let deadline = Instant::now() + Duration::from_secs(6);
        let mut last_count = 0usize;
        let mut last_change = Instant::now();
        loop {
            assert!(
                Instant::now() < deadline,
                "dispatch count never stabilized: {} dispatches and still \
                 moving — the burst is being absorbed without a window",
                last_count
            );
            std::thread::sleep(Duration::from_millis(25));
            let count = dispatched.load(Ordering::SeqCst);
            if count != last_count {
                last_count = count;
                last_change = Instant::now();
                continue;
            }
            if last_count > 0 && last_change.elapsed() > Duration::from_millis(300) {
                break; // stable
            }
        }
        assert!(
            last_count >= 1,
            "the burst never reached the dispatcher — vacuous pass"
        );
        assert!(
            last_count <= MAX_UNWRITTEN + SLACK,
            "a stalled-reader burst parked {last_count} responses — the \
             documented budget is {MAX_UNWRITTEN} (+{SLACK} in flight); \
             pre-window shape this marched to the 256-slot channel, \
             ~230 MiB per session"
        );

        // Teardown: stop the daemon; the dispatcher leaves the window on
        // the stop flag, the writer dies at its (shrunk) deadline and
        // shuts the socket down, which unblocks the parked pipeliner.
        stop.store(true, Ordering::SeqCst);
        let _ = served.join();
        let _ = pipeliner.join();
    }
}
