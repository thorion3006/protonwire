//! Deadline arithmetic shared by the request path (the r11 tracked
//! item, extracted): one place computes "the remaining budget" and
//! the degenerate cases, so the client's reads/writes and any
//! server-side mirroring cannot drift apart.

use std::time::{Duration, Instant};

/// The remaining budget from `now` until `deadline`.
///
/// The degenerate cases are explicit: an already-passed deadline
/// yields [`Duration::ZERO`] (never a panic, never a negative), and
/// the result is otherwise `deadline - now` clamped to `cap` — a
/// caller can bound any single wait below the logical deadline (the
/// socket's poll cadence) without recomputing the ceiling itself.
pub fn remaining_within(deadline: Instant, now: Instant, cap: Duration) -> Duration {
    let Some(remaining) = deadline.checked_duration_since(now) else {
        return Duration::ZERO;
    };
    remaining.min(cap)
}

/// Whether the deadline has passed at `now`.
pub fn expired(deadline: Instant, now: Instant) -> bool {
    now >= deadline
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_is_the_clamped_difference() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);
        let unclamped = remaining_within(deadline, now, Duration::from_secs(10));
        assert!(
            (Duration::from_secs(4)..=Duration::from_secs(5)).contains(&unclamped),
            "the remainder minus scheduling skew, got {unclamped:?}"
        );
        // The cap clamps a longer remainder.
        assert_eq!(
            remaining_within(deadline, now, Duration::from_secs(1)),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn a_passed_deadline_is_zero_never_negative() {
        let now = Instant::now();
        assert_eq!(
            remaining_within(now - Duration::from_secs(1), now, Duration::from_secs(10)),
            Duration::ZERO
        );
        assert!(expired(now - Duration::from_millis(1), now));
        assert!(!expired(now + Duration::from_secs(1), now));
    }
}
