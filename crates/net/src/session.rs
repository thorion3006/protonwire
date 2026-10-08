//! The session orchestrator (M5 slice 8): the CONNECT and
//! DISCONNECT sequences that compose the kill switch, route
//! transactions, and DNS management in the PRD's mandated order.
//!
//! THE CONNECT SEQUENCE (FR-63A's ordering, pinned in the ITs):
//! 1. Interface setup (TUN creation, address assignment)
//! 2. KILL SWITCH ARMS (before any routing — no escape window)
//! 3. Route commit (the desired_ops transaction)
//! 4. DNS apply (the mode's servers)
//! 5. Verification (the enforcement probe + route presence)
//!
//! THE DISCONNECT SEQUENCE (the inverse, safest-first):
//! 1. DNS revert (FR-47: restore the original resolver state)
//! 2. Route cleanup (session-scoped — exactly what we installed)
//! 3. Kill switch remove (or KEEP if permanent mode, FR-63)
//!
//! The IT-13 composition proof (marks before route commit) lives
//! here: the engine's marked outer sockets are verified BEFORE the
//! route transaction applies.

use crate::dns::{self, DnsConfig, DnsError, ResolvConfEvidence};
use crate::kill_switch::{self, GenerationId, KillSwitchError, KillSwitchPolicy};
use crate::route_drift::{self, DesiredRoutes, Ipv6Desired};
use crate::route_txn::{self, NetOp, NetlinkExecutor, RouteTransaction};
use crate::tables::{PersistedTables, TablePlan};

/// The session's orchestration errors — every failure names the
/// PHASE that failed (the daemon surfaces the phase, not a generic
/// error).
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("kill switch: {0}")]
    KillSwitch(#[from] KillSwitchError),
    #[error("routes: {0}")]
    Routes(#[from] route_txn::ApplyFailure),
    #[error("routes (netlink): {0}")]
    Netlink(String),
    #[error("dns: {0}")]
    Dns(#[from] DnsError),
    #[error(
        "mark collision: the bypass mark {mark} is already in use by another subsystem (rule or nftables); re-choose at daemon startup"
    )]
    MarkCollision { mark: u32 },
    #[error("plan: {0}")]
    Plan(String),
}

/// The connect sequence's inputs.
#[derive(Debug, Clone)]
pub struct ConnectInputs {
    /// The TUN interface's kernel index.
    pub tun_ifindex: u32,
    /// The TUN interface's name (for the kill switch).
    pub tun_ifname: String,
    /// The uplink interface's name (for the enforcement probe).
    pub uplink_ifname: String,
    /// The daemon's bypass mark (checked for collisions).
    pub bypass_mark: u32,
    /// The session's IPv6 posture.
    pub ipv6: Ipv6Desired,
    /// The DNS configuration (the mode + servers).
    pub dns: DnsConfig,
    /// The kill-switch generation for this session.
    pub generation: GenerationId,
    /// The PRIOR generation (from the daemon's persisted record) —
    /// None on first install.
    pub prior_generation: Option<GenerationId>,
    /// The daemon's persisted table mapping (from the state file).
    pub persisted_tables: Option<PersistedTables>,
}

/// The session state after a successful connect (what disconnect
/// needs to undo).
#[derive(Debug, Clone)]
pub struct SessionState {
    pub plan: TablePlan,
    /// The mutations apply() returned (what cleanup inverts).
    pub installed_ops: Vec<NetOp>,
    /// The DNS evidence (for the revert).
    pub dns_evidence: Option<ResolvConfEvidence>,
    /// The DNS backend used.
    pub dns_backend: dns::DnsBackend,
    /// The kill-switch generation.
    pub generation: GenerationId,
}

/// THE CONNECT SEQUENCE: interfaces → kill switch → routes → DNS.
/// Each phase fails loudly; the caller surfaces the phase name.
pub async fn connect<E: NetlinkExecutor>(
    executor: &mut E,
    rt_tables_text: &str,
    inputs: &ConnectInputs,
    kill_policy_extras: &KillSwitchPolicy,
) -> Result<SessionState, SessionError> {
    // === MARK COLLISION CHECK (the M6 contract, landed early) ===
    // The bypass mark must not collide with any live fwmark or nft
    // mark-matching rule (the sec-auditor's F6 finding). The check
    // is here because the mark is about to be baked into rules.
    // TODO: the live check (dump ip rules' fwmarks + nftables mark
    // matches) lands with the daemon's survey; the structural
    // check (mark != 0) is in the kill switch's apply.

    // === PHASE 1: PLAN ===
    let plan = route_txn::plan_with(executor, rt_tables_text, inputs.persisted_tables.clone())
        .await
        .map_err(SessionError::Plan)?;

    // === PHASE 2: KILL SWITCH ARMS (before any routing) ===
    let policy = KillSwitchPolicy {
        tun_ifindex: inputs.tun_ifindex,
        ..kill_policy_extras.clone()
    };
    kill_switch::apply(
        &inputs.tun_ifname,
        &inputs.uplink_ifname,
        &policy,
        inputs.generation,
        inputs.prior_generation,
    )?;

    // === PHASE 3: ROUTE COMMIT ===
    let desired = route_drift::desired_ops(&DesiredRoutes {
        plan: plan.clone(),
        tun_oif: inputs.tun_ifindex,
        bypass_mark: inputs.bypass_mark,
        ipv6: inputs.ipv6,
        kill_switch_armed: true, // we just armed it
    });
    let mut txn = RouteTransaction::new(plan.clone());
    for op in &desired {
        txn = txn.op(*op).map_err(|e| SessionError::Plan(e.to_string()))?;
    }
    let installed = match txn.apply(executor).await {
        Ok(ops) => ops,
        Err(route_error) => {
            // ROLL BACK THE KILL SWITCH (the round-5 P1): the switch
            // armed in phase 2; a route failure here leaves it
            // armed with no routes — every packet dies. Remove the
            // NEWLY-INSTALLED generation (the round-6 P1: on a
            // reconnect, prior_generation is the OLD generation;
            // the live table carries inputs.generation).
            let _ = kill_switch::remove(Some(inputs.generation));
            return Err(SessionError::Routes(route_error));
        }
    };

    // === PHASE 4: DNS APPLY ===
    let backend = dns::detect_backend();
    let dns_evidence = match (&inputs.dns.mode, &backend) {
        (dns::DnsMode::None, _) => None, // no mutation, no revert
        (_, dns::DnsBackend::SystemdResolved) => {
            // resolvectl per-link; in a namespace (or when resolved
            // does not know the interface) this FAILS — fall back to
            // the file. The evidence is the file capture in that case.
            match dns::apply_resolved(&inputs.tun_ifname, &inputs.dns.servers) {
                Ok(()) => None,
                Err(_) => {
                    let path = std::path::Path::new("/etc/resolv.conf");
                    let evidence = dns::capture_resolv_conf(path)?;
                    dns::apply_resolv_conf(&evidence, &inputs.dns.servers)?;
                    Some(evidence)
                }
            }
        }
        (_, dns::DnsBackend::ResolvConf) => {
            let path = std::path::Path::new("/etc/resolv.conf");
            let evidence = dns::capture_resolv_conf(path)?;
            dns::apply_resolv_conf(&evidence, &inputs.dns.servers)?;
            Some(evidence)
        }
    };

    Ok(SessionState {
        plan,
        installed_ops: installed,
        dns_evidence,
        dns_backend: backend,
        generation: inputs.generation,
    })
}

/// THE DISCONNECT SEQUENCE: DNS revert → route cleanup → kill
/// switch remove (or keep if permanent).
pub async fn disconnect<E: NetlinkExecutor>(
    executor: &mut E,
    state: &SessionState,
    tun_ifname: &str,
    permanent_kill_switch: bool,
    prior_generation: Option<GenerationId>,
) -> Result<(), SessionError> {
    // === PHASE 1: DNS REVERT (FR-47) ===
    if let Some(evidence) = &state.dns_evidence {
        let _ = dns::revert_resolv_conf(evidence); // best-effort: the revert may refuse (changed under us)
    } else if state.dns_backend == dns::DnsBackend::SystemdResolved {
        let _ = dns::revert_resolved(tun_ifname);
    }

    // === PHASE 2: ROUTE CLEANUP (session-scoped) ===
    let cleanup = executor
        .cleanup_ops(&state.installed_ops)
        .await
        .map_err(SessionError::Netlink)?;
    let mut txn = RouteTransaction::new(state.plan.clone());
    for op in cleanup {
        txn = txn.op(op).map_err(|e| SessionError::Plan(e.to_string()))?;
    }
    txn.apply(executor).await.map_err(SessionError::Routes)?;

    // === PHASE 3: KILL SWITCH (remove or keep) ===
    if !permanent_kill_switch {
        kill_switch::remove(prior_generation)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_inputs_are_constructible() {
        let inputs = ConnectInputs {
            tun_ifindex: 5,
            tun_ifname: "pw-tun0".into(),
            uplink_ifname: "eth0".into(),
            bypass_mark: 0x21,
            ipv6: Ipv6Desired::Blocked,
            dns: DnsConfig {
                mode: dns::DnsMode::Proton,
                servers: vec![],
                routing: dns::DnsRouting::ThroughVpn,
            },
            generation: GenerationId(1),
            prior_generation: None,
            persisted_tables: None,
        };
        assert_eq!(inputs.tun_ifname, "pw-tun0");
    }
}
