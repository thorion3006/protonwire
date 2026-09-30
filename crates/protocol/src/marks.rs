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

impl MarkApplier for SoMarkApplier {
    fn apply_mark(&self, socket_fd: RawFd) -> io::Result<()> {
        // nix's setsockopt takes an AsFd; protun hands over a borrowed
        // raw descriptor it owns for the duration of the callback.
        // SAFETY: socket_fd is an open descriptor (its owner, ProTUN's
        // socket factory, keeps it open for the whole callback — the
        // mark happens before the factory could close or reuse it).
        #[allow(unsafe_code)] // workspace deny; the one raw-fd borrow in the seam
        let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(socket_fd) };
        // SO_TYPE succeeds only on sockets: if a future protun ever
        // reports a stale fd the process has reused for something
        // else, refuse BEFORE marking an unrelated descriptor (the
        // contract drift becomes a recorded failure, not a silent
        // policy hole).
        nix::sys::socket::getsockopt(&fd, nix::sys::socket::sockopt::SockType)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        nix::sys::socket::setsockopt(&fd, nix::sys::socket::sockopt::Mark, &self.mark)
            .map_err(io::Error::from)
    }
}

/// The fail-closed health surface M5's route-commit lane gates on:
/// healthy only when every socket reported so far was marked
/// successfully AND at least one socket was reported at all (a cell
/// that saw zero sockets proves nothing — see [`MarkHealth::healthy`]).
#[derive(Debug)]
pub struct MarkHealth {
    all_marked: AtomicBool,
    reported: AtomicUsize,
}

impl MarkHealth {
    /// A healthy cell (nothing failed yet, nothing reported yet).
    pub fn new() -> Self {
        Self {
            all_marked: AtomicBool::new(true),
            reported: AtomicUsize::new(0),
        }
    }

    /// Whether every socket reported so far was marked successfully.
    /// Alone this is NOT the route-commit gate: a mis-wired callback
    /// that reports nothing leaves it `true` vacuously.
    pub fn all_marked(&self) -> bool {
        self.all_marked.load(Ordering::SeqCst)
    }

    /// How many sockets ProTUN reported through the callback. The M5
    /// FR-32B route-commit gate is **`all_marked() && reported() > 0`**
    /// — no full-tunnel route commits before at least one outer socket
    /// carried the bypass mark.
    pub fn reported(&self) -> usize {
        self.reported.load(Ordering::SeqCst)
    }

    /// The M5 route-commit gate, one call: every reported socket
    /// marked, and at least one reported (fail-closed against both the
    /// mark failure and the vacuous no-socket case).
    pub fn healthy(&self) -> bool {
        self.all_marked() && self.reported() > 0
    }

    fn note_failure(&self) {
        self.all_marked.store(false, Ordering::SeqCst);
    }

    fn note_reported(&self) {
        self.reported.fetch_add(1, Ordering::SeqCst);
    }
}

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
        self.health.note_reported();
        if let Err(error) = self.applier.apply_mark(socket_fd) {
            self.health.note_failure();
            tracing::warn!(
                socket_fd,
                error = %error,
                "outer-socket bypass mark failed (FR-32B) — route commit must refuse until resolved"
            );
        }
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
}
