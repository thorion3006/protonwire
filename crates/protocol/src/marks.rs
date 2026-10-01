//! Outer-socket bypass marks (PRD FR-32B; the seam IT-13 verifies
//! end-to-end in M5).
//!
//! ProTUN reports every outer-socket file descriptor the moment it
//! creates it — before the socket connects. ProtonWire must translate
//! that callback into the stable bypass mark (SO_MARK) so M5's policy
//! routes can exempt VPN-own traffic: a marked socket's packets skip
//! the full-tunnel routes and cannot loop back into the tunnel.
//!
//! The ordering guarantee (mark **before** any full-tunnel route is
//! committed) is the composition of two facts this module pins:
//!
//! 1. ProTUN invokes the callback at socket-creation time, before
//!    `connect(2)` — the socket cannot emit routeable traffic
//!    unmarked;
//! 2. [`MarkingFdCallback`] applies the mark synchronously inside the
//!    callback, so the descriptor is marked before the callback
//!    returns.
//!
//! M5's route-commit lane consumes [`MarkHealth`] fail-closed: while
//! any reported socket failed to mark, full-tunnel routes are not
//! committed (IT-13's live proof).

use std::io;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use protun::api::connection_unix::OnSocketFdAvailableCallback;

/// Applies the bypass mark to one reported outer-socket descriptor.
pub trait MarkApplier: Send + Sync {
    /// Mark `socket_fd` into the bypass policy. Must complete before
    /// the socket carries routeable traffic (the callback runs at
    /// socket-creation time).
    fn apply_mark(&self, socket_fd: RawFd) -> io::Result<()>;
}

/// `SO_MARK` implementation of [`MarkApplier`] — the FR-32B stable
/// bypass mark M5's policy routes match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoMarkApplier {
    mark: u32,
}

impl SoMarkApplier {
    /// A new applier setting `mark` on every reported descriptor.
    pub fn new(mark: u32) -> Self {
        Self { mark }
    }

    /// The configured mark value.
    pub fn mark(&self) -> u32 {
        self.mark
    }
}

/// The bot round's P2: raw fd values cross the SAFE `apply_mark`
/// api, so no `BorrowedFd` may be constructed from them — its
/// "descriptor is open and stays open" precondition is unverifiable
/// for an arbitrary i32, and a closed/reused fd would be UB through
/// safe Rust. Direct libc syscalls have no such invariant: the
/// KERNEL rejects invalid descriptors with EBADF, a benign typed
/// error.
impl MarkApplier for SoMarkApplier {
    fn apply_mark(&self, socket_fd: RawFd) -> io::Result<()> {
        // SO_TYPE succeeds only on sockets: a stale/reused fd fails
        // BEFORE an unrelated descriptor gets marked (contract drift
        // becomes a recorded failure, not a silent policy hole).
        ensure_socket(socket_fd)?;
        set_mark(socket_fd, self.mark)
    }
}

/// The socket check the caller's contract exercises: the descriptor
/// must BE a socket before it gets marked (the returned c_int is
/// the type — the check is the point, not the value).
#[allow(unsafe_code)] // workspace deny; leaf syscall, no pointers beyond the value args
fn ensure_socket(socket_fd: RawFd) -> io::Result<libc::c_int> {
    let mut socket_type: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: socket_fd is passed by value; the out-pointer and
    // length name a properly initialized c_int. An invalid fd
    // yields EBADF from the kernel.
    let rc = unsafe {
        libc::getsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::addr_of_mut!(socket_type).cast(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket_type)
}

/// The FR-32B stable bypass mark, one descriptor at a time.
#[allow(unsafe_code)] // workspace deny; leaf syscall, no pointers beyond the value args
fn set_mark(socket_fd: RawFd, mark: u32) -> io::Result<()> {
    // SAFETY: socket_fd and mark pass by value; the value pointer
    // names the u32 argument SO_MARK reads.
    let rc = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::addr_of!(mark).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
/// The fail-closed health surface M5's route-commit lane gates on:
/// healthy only when every socket reported so far was marked
/// successfully AND at least one socket was reported at all (a cell
/// that saw zero sockets proves nothing — see [`MarkHealth::healthy`]).
///
/// The fail-closed health surface M5's route-commit lane gates on:
/// healthy only when every socket reported so far was marked
/// successfully AND at least one socket was reported at all (a cell
/// that saw zero sockets proves nothing — see [`MarkHealth::healthy`]).
///
/// The state is ONE atomic word: `reported << 2 | in_flight << 1 |
/// failed`, where **in-flight is a COUNT** (the bot round-14 P1:
/// overlapping callbacks each add 1; a single bit let the first
/// completion clear the second's admission, and its later
/// completion subtracted into the neighboring fields). Admission,
/// completion, and the failure latch are each ONE RMW the reader's
/// single load observes entirely.
#[derive(Debug)]
pub struct MarkHealth {
    state: AtomicUsize,
}

impl MarkHealth {
    /// A healthy cell (nothing failed yet, nothing reported yet).
    pub fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
        }
    }

    /// Whether every socket reported so far was marked successfully.
    /// Alone this is NOT the route-commit gate: a mis-wired callback
    /// that reports nothing leaves it `true` vacuously.
    pub fn all_marked(&self) -> bool {
        self.state.load(Ordering::SeqCst) & FAILED == 0
    }

    /// How many sockets ProTUN reported through the callback. The M5
    /// FR-32B route-commit gate is **`all_marked() && reported() > 0`**
    /// — no full-tunnel route commits before at least one outer socket
    /// carried the bypass mark.
    pub fn reported(&self) -> usize {
        self.state.load(Ordering::SeqCst) >> REPORTED_SHIFT
    }

    /// How many callbacks are currently inside the applier.
    pub fn in_flight(&self) -> usize {
        (self.state.load(Ordering::SeqCst) & IN_FLIGHT_MASK) >> IN_FLIGHT_SHIFT
    }

    /// The M5 route-commit gate, one call: every reported socket
    /// marked, at least one reported, and NOTHING IN FLIGHT — the
    /// single-word state makes the whole conjunction one snapshot.
    ///
    /// NOTE THE RESIDUAL WINDOW (the bot round-14 second P1,
    /// disclosed): this is a CHECK, not a reservation — a callback
    /// admitted after this load can still be in flight when the
    /// caller commits. Closing check-to-act requires the commit side
    /// to hold the same lock the callbacks take (or a generation
    /// handshake); that belongs to M5's route-commit lane, which owns
    /// the act. The honest contract here: healthy() is a correct
    /// snapshot AT CALL TIME.
    pub fn healthy(&self) -> bool {
        let state = self.state.load(Ordering::SeqCst);
        state >> REPORTED_SHIFT > 0 && state & (IN_FLIGHT_MASK | FAILED) == 0
    }

    fn note_in_flight(&self) {
        self.state.fetch_add(IN_FLIGHT_UNIT, Ordering::SeqCst);
    }

    fn note_failure(&self) {
        self.state.fetch_or(FAILED, Ordering::SeqCst);
    }

    fn note_reported(&self) {
        self.state.fetch_add(REPORTED_UNIT, Ordering::SeqCst);
    }

    fn note_done(&self) {
        self.state.fetch_sub(IN_FLIGHT_UNIT, Ordering::SeqCst);
    }
}

/// The in-flight COUNT's field (multi-bit: overlapping callbacks).
const IN_FLIGHT_SHIFT: usize = 1;
const IN_FLIGHT_MASK: usize = 0x3FFF << IN_FLIGHT_SHIFT;
const IN_FLIGHT_UNIT: usize = 1 << IN_FLIGHT_SHIFT;
/// The failure latch: any mark failure, permanent.
const FAILED: usize = 1 << 0;
/// The reported counter's unit.
const REPORTED_UNIT: usize = 1 << 15;
/// The reported counter's shift.
const REPORTED_SHIFT: usize = 15;

impl Default for MarkHealth {
    /// Delegates to [`MarkHealth::new`] (healthy): `Default` must agree
    /// with `new()` — a derived `Default` would start `all_marked`
    /// false and permanently fail-close the route-commit lane with no
    /// failure anywhere to explain it.
    fn default() -> Self {
        Self::new()
    }
}

/// The ProTUN-side callback: every descriptor ProTUN reports is marked
/// synchronously, and a mark failure flips the shared
/// [`MarkHealth`] cell the route-commit lane consumes (the callback's
/// own signature returns `()` — it cannot refuse the socket to
/// ProTUN, so the refusal happens one lane later, fail-closed).
pub struct MarkingFdCallback {
    applier: Arc<dyn MarkApplier>,
    health: Arc<MarkHealth>,
}

impl MarkingFdCallback {
    /// Wraps `applier`, reporting health into `health`.
    pub fn new(applier: Arc<dyn MarkApplier>, health: Arc<MarkHealth>) -> Self {
        Self { applier, health }
    }
}

impl OnSocketFdAvailableCallback for MarkingFdCallback {
    fn on_socket_fd_available(&self, socket_fd: i32) {
        // Synchronous: by the time this returns, the descriptor carries
        // the bypass mark (or the failure is recorded for the
        // fail-closed gate — the callback cannot refuse the socket).
        // PUBLISH-AFTER-OUTCOME (the bot round's P1): `reported` is
        // counted only once the marking RESULT is in — a concurrent
        // `healthy()` between report and outcome could otherwise see
        // reported>0 with all_marked still true and commit routes
        // over an unmarked socket. Both orderings below are
        // fail-closed: the failure latch lands BEFORE the report; a
        // success records the report last.
        // The in-flight window: incremented BEFORE the applier runs,
        // decremented after the outcome is recorded (the bot round-12
        // P1 — healthy() refuses while any marking is in progress).
        self.health.note_in_flight();
        let outcome = self.applier.apply_mark(socket_fd);
        match outcome {
            Ok(()) => self.health.note_reported(),
            Err(ref error) => {
                self.health.note_failure();
                self.health.note_reported();
                tracing::warn!(
                    socket_fd,
                    error = %error,
                    "outer-socket bypass mark failed (FR-32B) — route commit must refuse until resolved"
                );
            }
        }
        self.health.note_done();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A recording stand-in for the SO_MARK applier (the live
    /// setsockopt round-trip needs CAP_NET_ADMIN — it rides the netns
    /// integration lane, IT-1's harness).
    #[derive(Default)]
    struct RecordingApplier {
        marked: Mutex<Vec<RawFd>>,
        fail: bool,
    }

    impl MarkApplier for RecordingApplier {
        fn apply_mark(&self, socket_fd: RawFd) -> io::Result<()> {
            if self.fail {
                Err(io::Error::other("mark refused"))
            } else {
                self.marked.lock().unwrap().push(socket_fd);
                Ok(())
            }
        }
    }

    #[test]
    fn callback_marks_every_reported_fd_synchronously() {
        let applier = Arc::new(RecordingApplier::default());
        let health = Arc::new(MarkHealth::new());
        let callback = MarkingFdCallback::new(applier.clone(), health.clone());

        callback.on_socket_fd_available(7);
        callback.on_socket_fd_available(9);

        assert_eq!(*applier.marked.lock().unwrap(), vec![7, 9]);
        assert_eq!(health.reported(), 2, "every report is counted");
        assert!(
            health.healthy(),
            "marks succeeded and sockets were reported"
        );
    }

    #[test]
    fn a_failed_mark_flips_health_and_never_panics() {
        let applier = Arc::new(RecordingApplier {
            marked: Mutex::new(Vec::new()),
            fail: true,
        });
        let health = Arc::new(MarkHealth::new());
        let callback = MarkingFdCallback::new(applier.clone(), health.clone());

        // ProTUN's callback contract is infallible on our side: the
        // failure is recorded, the thread lives on.
        callback.on_socket_fd_available(3);

        assert!(
            !health.all_marked(),
            "the route-commit gate must refuse now"
        );
        assert_eq!(
            health.reported(),
            1,
            "the failed socket still counts as reported"
        );
        assert!(!health.healthy());
        assert!(applier.marked.lock().unwrap().is_empty());
    }

    /// The vacuous case the M5 route-commit gate must refuse: a cell
    /// that saw ZERO sockets proves nothing — `all_marked()` alone
    /// stays `true`, `healthy()` does not. A mis-wired callback (or a
    /// future protun path creating outer sockets outside the factory)
    /// must fail closed, not pass open.
    #[test]
    fn zero_reported_sockets_is_not_healthy() {
        let health = MarkHealth::new();
        assert!(health.all_marked());
        assert_eq!(health.reported(), 0);
        assert!(
            !health.healthy(),
            "the gate is all_marked() && reported() > 0 — never all_marked() alone"
        );
    }

    /// `Default` must agree with `new()` (the derived `Default` would
    /// start the latch false and fail-close the lane with no failure
    /// to point at).
    #[test]
    fn default_agrees_with_new() {
        let by_default = MarkHealth::default();
        let by_new = MarkHealth::new();
        assert_eq!(by_default.all_marked(), by_new.all_marked());
        assert_eq!(by_default.reported(), by_new.reported());
        assert_eq!(by_default.healthy(), by_new.healthy());
    }

    /// The bot round-12 P1: a LATER callback still inside the
    /// applier is IN FLIGHT — healthy() refuses even though the
    /// earlier success left the latch green (routes must not commit
    /// over an unmarked in-flight socket).
    #[test]
    fn a_callback_in_flight_blocks_the_gate() {
        struct BlockingApplier {
            entered: Arc<std::sync::Barrier>,
            release: Arc<std::sync::Barrier>,
        }
        impl MarkApplier for BlockingApplier {
            fn apply_mark(&self, _socket_fd: RawFd) -> io::Result<()> {
                self.entered.wait();
                self.release.wait();
                Ok(())
            }
        }
        let health = Arc::new(MarkHealth::new());
        // A first SUCCESSFUL mark (the latch goes green, reported=1).
        let done = Arc::new(RecordingApplier::default());
        MarkingFdCallback::new(done, health.clone()).on_socket_fd_available(1);
        assert!(health.healthy(), "the first success opens the gate");
        // A second callback parks inside apply_mark.
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let parked = MarkingFdCallback::new(
            Arc::new(BlockingApplier {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }),
            Arc::clone(&health),
        );
        let handle = std::thread::spawn(move || parked.on_socket_fd_available(2));
        entered.wait();
        assert!(
            !health.healthy(),
            "the in-flight mark must refuse the gate even after a success"
        );
        release.wait();
        handle.join().unwrap();
        assert!(health.healthy(), "the gate reopens once the marking lands");
    }

    /// The bot round-14 P1: OVERLAPPING callbacks — the in-flight
    /// field is a COUNT, so the first completion does not clear the
    /// second's admission and no completion ever borrows into the
    /// neighboring fields.
    #[test]
    fn overlapping_admissions_are_counted_not_cleared() {
        struct ParkingApplier {
            entered: Arc<std::sync::Barrier>,
            release: Arc<std::sync::Barrier>,
        }
        impl MarkApplier for ParkingApplier {
            fn apply_mark(&self, _socket_fd: RawFd) -> io::Result<()> {
                self.entered.wait();
                self.release.wait();
                Ok(())
            }
        }
        let health = Arc::new(MarkHealth::new());
        let entered = Arc::new(std::sync::Barrier::new(3));
        let release = Arc::new(std::sync::Barrier::new(3));
        // TWO callbacks overlap inside apply_mark.
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let callback = MarkingFdCallback::new(
                    Arc::new(ParkingApplier {
                        entered: Arc::clone(&entered),
                        release: Arc::clone(&release),
                    }),
                    Arc::clone(&health),
                );
                std::thread::spawn(move || callback.on_socket_fd_available(1))
            })
            .collect();
        entered.wait();
        assert_eq!(health.in_flight(), 2, "both admissions are counted");
        assert!(!health.healthy());
        release.wait();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(
            health.in_flight(),
            0,
            "every completion decrements its own admission"
        );
        assert!(health.healthy(), "no field was corrupted by the overlap");
    }
}
