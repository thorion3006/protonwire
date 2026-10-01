//! `cargo xtask netns-it` — run every network-namespace-gated
//! integration test (PRD NFR-31) inside a private user + network
//! namespace, never on the host.
//!
//! `unshare --user --map-root-user --net` makes the process root of an
//! EMPTY network namespace: `CAP_NET_ADMIN` over `lo` and nothing
//! else. No real privilege is gained (the uid maps back to the calling
//! user), and no host interface, route, or rule can be touched.
//!
//! The runner enters through a tiny `sh -c` shim so the
//! namespace-identity nonce (`readlink /proc/self/ns/net`) is read
//! INSIDE the namespace and exported alongside the gate flag — a
//! leaked flag alone never arms the gated tests
//! ([`protonwire_net::netns::MANAGED_NETNS_ID_ENV`]).
//!
//! When the environment cannot create user namespaces (hardened
//! kernels, some containers), the runner DISCLOSES loudly (a GitHub
//! `::warning::` annotation, a step-summary line, and an executed-
//! count of zero) and exits successfully — a green job can never be
//! mistaken for a green test run.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::Reporter;

/// The netns-gated integration test binaries, in execution order.
/// M5's net-control suite appends its targets here.
const GATED_TARGETS: &[(&str, &str)] = &[("protonwire-protocol", "it_tun_lifecycle")];

/// `unshare` flags creating the isolated user + network namespace.
const UNSHARE_ARGS: &[&str] = &["--user", "--map-root-user", "--net"];

/// The shim between `unshare` and cargo: reads the namespace identity
/// inside the namespace, arms both gate variables, execs the test
/// cargo. `sh -c` passes the first trailing argument as `$0` — the
/// cargo binary — and the rest as `"$@"`. Built from the gate's own
/// constants so a renamed variable cannot silently disarm the harness
/// (both names are pinned on the net side).
fn gate_shim() -> String {
    use protonwire_net::netns::{MANAGED_NETNS_ENV, MANAGED_NETNS_ID_ENV};
    format!(
        "ns=$(readlink /proc/self/ns/net) && exec env \
         {MANAGED_NETNS_ENV}=1 {MANAGED_NETNS_ID_ENV}=\"$ns\" \"$0\" \"$@\""
    )
}

pub(crate) fn run(root: &Path) -> Result<bool> {
    let mut reporter = Reporter::new("netns-it");

    let userns_supported = probe_userns();
    if !userns_supported {
        let notice = "netns-it SKIPPED: this environment cannot create user \
                      namespaces (`unshare --user --map-root-user --net` refused). \
                      0 gated targets executed; the host was not touched. \
                      Run on a host with unprivileged user namespaces (NFR-31).";
        println!("SKIP [netns-it] {notice}");
        // CI visibility: a green job must not read as a green test run
        // (stdout alone is easy to miss in the Actions log sea).
        println!("::warning::{notice}");
        if let Ok(summary) = std::env::var("GITHUB_STEP_SUMMARY") {
            let _ = std::fs::write(summary, "### netns-it: SKIPPED (no user namespaces)\n");
        }
        reporter.rule("userns availability probe (skipped run)", &[]);
        println!(
            "netns-it: 0/{} gated targets executed (skipped)",
            GATED_TARGETS.len()
        );
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

    // BUILD OUTSIDE THE NAMESPACE (the bot round-11 P2): a fresh
    // checkout or a CI cache miss needs the registry network — a
    // namespace has none (loopback only, `lo` up), so cargo's fetch
    // would die inside it before any gated test ran. Every target
    // compiles here first (--no-run); the in-namespace invocation
    // below is then a no-network compile check away from running.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let mut build = Command::new(&cargo);
    build.arg("test").arg("--no-run");
    for (package, target) in GATED_TARGETS {
        build.args(["-p", package, "--test", target]);
    }
    build
        .args(&cargo_args)
        .status()
        .with_context(|| "compiling the gated targets outside the namespace (registry access)")?;

    let mut failures = Vec::new();
    for (package, target) in GATED_TARGETS {
        let label = format!("{package}::{target}");
        let status = Command::new("unshare")
            .args(UNSHARE_ARGS)
            .arg("--")
            .arg("/bin/sh")
            .arg("-c")
            .current_dir(root)
            .arg(gate_shim())
            .arg(&cargo)
            .arg("test")
            .args(&cargo_args)
            .args(["-p", package, "--test", target, "--", "--nocapture"])
            .status()
            .with_context(|| format!("spawning {label} inside the namespace"))?;
        if status.success() {
            reporter.rule(&label, &[]);
        } else {
            failures.push(format!("{label} exited with {status}"));
            reporter.rule(&label, &[format!("{label}: exit {status}")]);
        }
    }
    println!(
        "netns-it: {}/{} gated targets executed inside the namespace",
        GATED_TARGETS.len() - failures.len(),
        GATED_TARGETS.len()
    );
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
