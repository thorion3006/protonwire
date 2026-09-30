//! `cargo xtask netns-it` — run every network-namespace-gated
//! integration test (PRD NFR-31) inside a private user + network
//! namespace, never on the host.
//!
//! `unshare --user --map-root-user --net` makes the process root of an
//! EMPTY network namespace: `CAP_NET_ADMIN` over `lo` and nothing
//! else. No real privilege is gained (the uid maps back to the calling
//! user), and no host interface, route, or rule can be touched. The
//! runner sets [`protonwire_net::netns::MANAGED_NETNS_ENV`] for the
//! children so their [`netns::gate`] arms execute the tests; a plain
//! `cargo test` keeps them skipped with a disclosure line.
//!
//! When the environment cannot create user namespaces (hardened
//! kernels, some containers), the runner DISCLOSES and exits
//! successfully — the gate stays honest about what ran, and CI stays
//! green on hosts without the capability.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::Reporter;

/// The netns-gated integration test binaries, in execution order.
/// M5's net-control suite appends its targets here.
const GATED_TARGETS: &[(&str, &str)] = &[("protonwire-protocol", "it_tun_lifecycle")];

/// `unshare` flags creating the isolated user + network namespace.
const UNSHARE_ARGS: &[&str] = &["--user", "--map-root-user", "--net"];

pub(crate) fn run(_root: &Path) -> Result<bool> {
    let mut reporter = Reporter::new("netns-it");

    let userns_supported = probe_userns();
    if !userns_supported {
        println!(
            "SKIP [netns-it] this environment cannot create user namespaces \
             (`unshare --user --map-root-user --net` refused); the gated \
             integration tests did not run — nothing was executed, the host \
             was not touched. Run `cargo xtask netns-it` on a host with \
             unprivileged user namespaces (NFR-31)."
        );
        reporter.rule("userns availability probe", &[]);
        return Ok(true);
    }
    reporter.rule("userns availability probe", &[]);

    // `cargo xtask netns-it --locked` forwards the lockfile discipline
    // to the inner `cargo test` invocations (CI's FR-127A shape).
    let mut cargo_args = vec![];
    for arg in std::env::args().skip(2) {
        match arg.as_str() {
            "--locked" => cargo_args.push("--locked"),
            other => return Err(anyhow::anyhow!("unexpected netns-it argument: {other}")),
        }
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let mut failures = Vec::new();
    for (package, target) in GATED_TARGETS {
        let label = format!("{package}::{target}");
        let status = Command::new("unshare")
            .args(UNSHARE_ARGS)
            .arg("--")
            .arg(&cargo)
            .arg("test")
            .args(&cargo_args)
            .args(["-p", package, "--test", target, "--", "--nocapture"])
            .env(protonwire_net::netns::MANAGED_NETNS_ENV, "1")
            .status()
            .with_context(|| format!("spawning {label} inside the namespace"))?;
        if status.success() {
            reporter.rule(&label, &[]);
        } else {
            failures.push(format!("{label} exited with {status}"));
            reporter.rule(&label, &[format!("{label}: exit {status}")]);
        }
    }
    Ok(failures.is_empty())
}

/// Whether `unshare` can create the managed namespace here.
fn probe_userns() -> bool {
    Command::new("unshare")
        .args(UNSHARE_ARGS)
        .arg("--")
        .arg("true")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
