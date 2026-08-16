//! Allocation-count probe for the owned-secret registration path
//! (FU-E, from round-6 verdict residuals on pr-champion WO-2).
//!
//! W2's no-intermediate-copy property is portably testable after all: a
//! counting global allocator pins it exactly. A dedicated integration
//! test (its own binary, a single test) keeps the count deterministic —
//! unit tests in the lib would share the allocator with every other
//! test thread.

// Scoped `unsafe_code` allow, per the GUI-boundary precedent
// (apps/gui/src-tauri/Cargo.toml allows it for the Tauri FFI boundary
// while the workspace deny stays intact everywhere else): here unsafe is
// confined to the `GlobalAlloc` impl below — the standard counting-probe
// pattern, delegating verbatim to `std::alloc::System`.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use protonwire_core::redact::SecretString;

/// Total allocations since process start, process-wide.
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

/// `std::alloc::System` wrapped with a counter.
struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: layout forwarded verbatim to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: pointer/layout forwarded verbatim to the system
        // allocator; only `alloc` is counted, so dealloc stays a pure
        // pass-through.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// pr-champion WO-2 / FU-E: `SecretString::new(String)` must take the
/// caller's allocation by MOVE — `String` into `Zeroizing` into the `Arc`
/// box — with no intermediate `to_owned` copy of the secret. Pre-W2 code
/// (`register(&value)`) stranded an unzeroized temporary clone: 2
/// allocations (the `to_owned` plus the Arc box). The move path performs
/// exactly ONE (the Arc box). The count is why this lives in its own
/// integration-test binary with a single test: nothing else allocates
/// against the same counter.
#[test]
fn secret_string_new_moves_the_callers_allocation_in_exactly_one_alloc() {
    // Warm-up registration (qa's determinism trick): settle the scrub
    // registry Vec's capacity so the `push` inside registration cannot
    // itself allocate. Each warm-up secret registers (length above the
    // minimum) and dies immediately; the registry prunes the dead weak
    // entries on the next registration but keeps the Vec's capacity.
    for i in 0..8 {
        drop(SecretString::new(format!("warm-up-secret-{i:04}")));
    }

    // The probe: constructed before the counter snapshot, so the String
    // literal's own allocation is outside the measured window.
    let value = String::from("tok-single-allocation-0001");
    let before = ALLOCATIONS.load(Ordering::SeqCst);
    let secret = SecretString::new(value);
    let after = ALLOCATIONS.load(Ordering::SeqCst);
    assert_eq!(
        secret.expose(),
        "tok-single-allocation-0001",
        "the value must survive the move intact"
    );
    assert_eq!(
        after - before,
        1,
        "the owned-secret path must make exactly one allocation (the Arc \
         box); 2 means the value was cloned/to_owned'd on the way in"
    );
}
