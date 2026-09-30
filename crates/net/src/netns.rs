//! Network-namespace integration-test harness (PRD NFR-31).
//!
//! Integration tests mutate kernel networking state (create interfaces,
//! add routes, load firewall rules). They must never touch the host:
//! the runner (`cargo xtask netns-it`) executes each gated test binary
//! inside a private user + network namespace (`unshare --user
//! --map-root-user --net`), where the process is root *of an empty
//! network namespace* — `CAP_NET_ADMIN` over `lo` and nothing else, no
//! real privilege, no host mutation.
//!
//! Test binaries consult [`gate`] first. Outside the runner every gated
//! test *skips with a disclosure line* naming the command to run — a
//! plain `cargo test` (CI unit lane, developer shells) stays green
//! while the integration lane stays opt-in and observable.
//!
//! Inside the namespace, `/proc/net` (a symlink to `/proc/self/net`)
//! reflects the isolated interface set; `/sys/class/net` does **not**
//! (sysfs is mounted once for the host) — tests must observe kernel
//! state through netlink or `/proc/net`, never through sysfs.

/// Set to `1` by [`crate::netns`]'s runner for test processes executing
/// inside the managed network namespace. The only lane that enables it:
/// a manual `sudo cargo test` does NOT set it, so even a real root run
/// skips rather than mutating the host namespace.
pub const MANAGED_NETNS_ENV: &str = "PROTONWIRE_TEST_NETNS";

/// Whether this process runs inside the managed network namespace.
pub fn in_managed_netns() -> bool {
    std::env::var_os(MANAGED_NETNS_ENV).is_some_and(|value| value == "1")
}

/// The skip gate every netns integration test opens with.
///
/// Returns `true` when the test must run; `false` after printing the
/// disclosure line (the caller returns immediately — nothing ran, the
/// host is untouched).
///
/// ```no_run
/// #[test]
/// fn it_example() {
///     if !protonwire_net::netns::gate("IT-1 tun lifecycle") {
///         return;
///     }
///     // …kernel-mutating assertions, safe inside the namespace…
/// }
/// ```
pub fn gate(test_id: &str) -> bool {
    gate_in(test_id, in_managed_netns())
}

fn gate_in(test_id: &str, enabled: bool) -> bool {
    if enabled {
        true
    } else {
        eprintln!(
            "SKIP [{test_id}]: requires an isolated network namespace (NFR-31) — \
             run `cargo xtask netns-it`; nothing executed, the host was not touched"
        );
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_in_disabled_discloses_and_skips() {
        // The pure arm: a disabled gate returns false (the caller skips);
        // the disclosure itself goes to stderr, asserted by convention —
        // `cargo test -- --nocapture` shows it in the red/green record.
        assert!(!gate_in("unit-gate-probe", false));
    }

    #[test]
    fn gate_in_enabled_runs() {
        assert!(gate_in("unit-gate-probe", true));
    }

    #[test]
    fn the_env_flag_is_the_runner_contract() {
        // The runner (xtask netns-it) and the gate must agree on the
        // exact flag; xtask imports this constant.
        assert_eq!(MANAGED_NETNS_ENV, "PROTONWIRE_TEST_NETNS");
    }
}
