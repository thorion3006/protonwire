//! `protonwire-credential-agent` — skeleton (PRD 6.3, 7.1A).
//!
//! The credential agent is the only component that touches a user's
//! desktop keyring. It runs as the account owner's UID, registers outbound
//! to the root daemon (never the reverse: the daemon must never join a user
//! D-Bus session), and serves bounded opaque load/store/delete operations
//! over allowlisted record kinds. Neither side accepts a caller-supplied
//! target UID.
//!
//! Milestone 2 implements the registration protocol and the Secret
//! Service/KWallet backend; Milestone 2's integration tests IT-29 cover the
//! mutual peer-credential enforcement.

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "protonwire-credential-agent",
    version,
    about = "ProtonWire per-user credential agent (skeleton)"
)]
struct Args {
    /// Report agent status without starting the service loop.
    #[arg(long)]
    status: bool,
}

fn main() {
    let args = Args::parse();
    if args.status {
        println!("credential agent: skeleton (protocol lands in milestone 2, PRD 7.1A)");
        return;
    }
    eprintln!(
        "protonwire-credential-agent: the agent protocol is not implemented in milestone 1 \
         (planned: milestone 2 — keyring broker registering outbound to the daemon)"
    );
    std::process::exit(1);
}
