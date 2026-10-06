//! The nftables kill switch (FR-56..65, M5 slice 4): a dedicated,
//! ATOMICALLY REPLACED `inet protonwire` table whose output base
//! chain defaults to DROP — non-VPN traffic dies in the kernel
//! (G-7), v4 AND v6 (FR-62: an inet-family default drop needs no
//! per-family rules to leak-proof both).
//!
//! Ownership (FR-59): the table carries a MARKER CHAIN named
//! `pw-gen-<16-hex>` — the generation of the apply that created it,
//! persisted by the daemon alongside its table mapping. A `protonwire`
//! table WITHOUT our marker is a LOOKALIKE: apply refuses, nothing is
//! flushed, the caller fails closed (FR-65). Rules are built as
//! netlink data — no shell, no interpolated `nft` command.
//!
//! Permitted traffic (FR-61): loopback, the TUN itself, the exact
//! v4 DHCP bootstrap (udp/67), the daemon's bypass MARK (sockets
//! ProTUN itself marked — identity, not a destination allowlist),
//! and the LAN interface when LAN access is enabled. Everything
//! else — including IPv6 — hits the default drop with a COUNTER on
//! it (the netns IT reads that counter back as the enforcement
//! proof).
//!
//! Validation (FR-64/65): [`crate::kill_switch::validate`] re-dumps the table after
//! apply and proves the marker generation, the drop-policy output
//! chain, and the exact rendered rule count — anything else is an
//! error, never a silent maybe.

use rustables::expr::{
    Cmp, CmpOp, Counter, HighLevelPayload, Immediate, Meta, MetaType, TransportHeaderField,
    UDPHeaderField, VerdictKind,
};
use rustables::{
    Batch, Chain, ChainPolicy, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table, iface_index,
    list_chains_for_table, list_tables,
};

/// The kill switch's dedicated table (FR-59: `inet protonwire`).
pub const TABLE_NAME: &str = "protonwire";
/// The output base chain: policy DROP is the kill.
pub const OUTPUT_CHAIN: &str = "pw-output";
/// The ownership marker chain's name prefix; the suffix is the
/// 16-hex apply generation.
pub const MARKER_PREFIX: &str = "pw-gen-";

/// What a connected session needs permitted through the kill switch
/// (FR-61's exact allowlist — everything else drops).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillSwitchPolicy {
    /// The TUN interface's kernel index (its traffic is the VPN's
    /// own — always permitted).
    pub tun_ifindex: u32,
    /// Permit v4 DHCP bootstrap (udp/67) — the active uplink's
    /// lease renewal while the tunnel is down or establishing.
    pub allow_dhcp_v4: bool,
    /// The LAN interface's kernel index when LAN access is enabled
    /// (FR-36; exact-CIDR LAN scoping rides the LAN slice).
    pub lan_ifindex: Option<u32>,
    /// The daemon's private bypass mark — only sockets the active
    /// daemon/ProTUN instance marked match (identity, not a
    /// destination allowlist; FR-61).
    pub bypass_mark: u32,
}

/// The generation of one kill-switch apply — persisted by the
/// daemon, bumped every apply, encoded in the marker chain's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerationId(pub u64);

impl GenerationId {
    /// The marker chain name for this generation.
    pub fn marker_chain_name(self) -> String {
        format!("{MARKER_PREFIX}{:016x}", self.0)
    }

    /// Parse a chain name back into a generation — `None` for
    /// anything that is not OUR marker (the ownership check).
    pub fn from_chain_name(name: &str) -> Option<Self> {
        let hex = name.strip_prefix(MARKER_PREFIX)?;
        if hex.len() != 16 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(hex, 16).ok().map(GenerationId)
    }
}

/// What apply should do with the nftables state it found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyDecision {
    /// No `protonwire` table exists — a fresh install.
    FreshApply,
    /// Our marker chain is present — an OWNED replace (atomic
    /// delete+recreate in one batch).
    ReplaceOwned(GenerationId),
    /// A `protonwire` table exists with NO marker of ours — a
    /// lookalike: refuse, flush nothing, fail closed (FR-59/65).
    RefuseLookalike,
}

/// Decide the apply from the observed nftables state (pure): `None`
/// = no table (fresh); `Some(markers)` = the table's marker chains —
/// empty markers on an EXISTING table is exactly the lookalike case
/// (a fresh apply over it would be a flush of unowned state).
pub fn decide_live(table_markers: Option<&[GenerationId]>) -> ApplyDecision {
    match table_markers {
        None => ApplyDecision::FreshApply,
        Some([]) => ApplyDecision::RefuseLookalike,
        Some(markers) => ApplyDecision::ReplaceOwned(*markers.last().expect("non-empty")),
    }
}

// ---------------------------------------------------------------------------
// The live surface: probe, apply, validate, remove.
// ---------------------------------------------------------------------------

/// Every kill-switch failure mode fails CLOSED — the caller must
/// treat the kill switch as unenforced (FR-65).
#[derive(Debug, thiserror::Error)]
pub enum KillSwitchError {
    #[error(
        "a `protonwire` nftables table exists without our marker chain — a lookalike; nothing flushed, failing closed (FR-59)"
    )]
    Lookalike,
    #[error("netfilter: {0}")]
    Netfilter(String),
    #[error(
        "post-apply validation failed: {0} — the kill switch is NOT proven enforced (FR-64/65)"
    )]
    Validation(String),
    #[error("interface {0} has no kernel index")]
    MissingInterface(String),
}

impl From<rustables::error::QueryError> for KillSwitchError {
    fn from(error: rustables::error::QueryError) -> Self {
        KillSwitchError::Netfilter(error.to_string())
    }
}

impl From<rustables::error::BuilderError> for KillSwitchError {
    fn from(error: rustables::error::BuilderError) -> Self {
        KillSwitchError::Netfilter(error.to_string())
    }
}

impl From<std::io::Error> for KillSwitchError {
    fn from(error: std::io::Error) -> Self {
        KillSwitchError::Netfilter(error.to_string())
    }
}

fn our_table() -> Result<Option<Table>, KillSwitchError> {
    for table in list_tables()? {
        if table.get_name().is_some_and(|name| name == TABLE_NAME) {
            return Ok(Some(table));
        }
    }
    Ok(None)
}

/// The marker generations found in the live `protonwire` table
/// (zero or one in practice; a marker-shaped chain set).
fn marker_generations(table: &Table) -> Result<Vec<GenerationId>, KillSwitchError> {
    let mut found = Vec::new();
    for chain in list_chains_for_table(table)? {
        if let Some(generation) = chain
            .get_name()
            .and_then(|name| GenerationId::from_chain_name(name.as_str()))
        {
            found.push(generation);
        }
    }
    Ok(found)
}

/// How many rules [`render_rules`] produces for a policy — the
/// validation's exact count (FR-64).
fn expected_rule_count(policy: &KillSwitchPolicy) -> usize {
    2 /* tun + loopback */
        + usize::from(policy.allow_dhcp_v4)
        + usize::from(policy.lan_ifindex.is_some())
        + 1 /* bypass mark */
        + 1 /* the counted terminal drop */
}

fn allow_oif(chain: &Chain, ifindex: u32) -> Result<Rule, KillSwitchError> {
    Ok(Rule::new(chain)?
        .with_expr(Meta::new(MetaType::Oif))
        .with_expr(Cmp::new(CmpOp::Eq, ifindex.to_le_bytes()))
        .with_expr(Immediate::new_verdict(VerdictKind::Accept)))
}

/// The output chain's rules in evaluation order: specific permits
/// first, the counted terminal drop last (the counter is the IT's
/// enforcement proof).
fn render_rules(chain: &Chain, policy: &KillSwitchPolicy) -> Result<Vec<Rule>, KillSwitchError> {
    let mut rules = vec![
        allow_oif(chain, policy.tun_ifindex)?,
        allow_oif(chain, iface_index("lo")? as u32)?,
    ];
    if policy.allow_dhcp_v4 {
        rules.push(
            Rule::new(chain)?
                .with_expr(
                    HighLevelPayload::Transport(TransportHeaderField::Udp(UDPHeaderField::Dport))
                        .build(),
                )
                .with_expr(Cmp::new(CmpOp::Eq, 67_u16.to_le_bytes()))
                .with_expr(Immediate::new_verdict(VerdictKind::Accept)),
        );
    }
    if let Some(lan_ifindex) = policy.lan_ifindex {
        rules.push(allow_oif(chain, lan_ifindex)?);
    }
    rules.push(
        Rule::new(chain)?
            .with_expr(Meta::new(MetaType::Mark))
            .with_expr(Cmp::new(CmpOp::Eq, policy.bypass_mark.to_le_bytes()))
            .with_expr(Immediate::new_verdict(VerdictKind::Accept)),
    );
    rules.push(
        Rule::new(chain)?
            .with_expr(Counter::default())
            .with_expr(Immediate::new_verdict(VerdictKind::Drop)),
    );
    Ok(rules)
}

/// Atomically install the kill switch at `generation`: decide
/// ownership (refusing lookalikes), then ONE batch — delete the
/// owned table if present, recreate table + marker + output chain +
/// rules — and validate + behaviorally probe the result. `tun_ifname`
/// is resolved to its kernel index (the policy speaks indices; names
/// drift); `uplink_ifname` is the enforcement probe's forced egress.
pub fn apply(
    tun_ifname: &str,
    uplink_ifname: &str,
    policy: &KillSwitchPolicy,
    generation: GenerationId,
) -> Result<(), KillSwitchError> {
    let tun_ifindex = iface_index(tun_ifname)
        .map_err(|_| KillSwitchError::MissingInterface(tun_ifname.to_owned()))?
        as u32;
    let policy = KillSwitchPolicy {
        tun_ifindex,
        ..policy.clone()
    };

    let existing = our_table()?;
    let markers = match &existing {
        Some(table) => marker_generations(table)?,
        None => Vec::new(),
    };
    match decide_live(existing.as_ref().map(|_| markers.as_slice())) {
        ApplyDecision::RefuseLookalike => return Err(KillSwitchError::Lookalike),
        ApplyDecision::FreshApply | ApplyDecision::ReplaceOwned(_) => {}
    }

    let mut batch = Batch::new();
    if let Some(table) = existing {
        batch.add(&table, MsgType::Del);
    }
    let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME);
    batch.add(&table, MsgType::Add);
    batch.add(
        &Chain::new(&table).with_name(generation.marker_chain_name()),
        MsgType::Add,
    );
    let output = Chain::new(&table)
        .with_name(OUTPUT_CHAIN)
        .with_hook(Hook::new(HookClass::Out, 0))
        .with_policy(ChainPolicy::Drop);
    batch.add(&output, MsgType::Add);
    for rule in render_rules(&output, &policy)? {
        batch.add(&rule, MsgType::Add);
    }
    batch.send()?;
    validate(&policy, generation)?;
    enforcement_probe(uplink_ifname)
}

/// FR-64: re-dump the live table and prove what we just applied —
/// the marker generation, the output base chain, the exact rendered
/// rule count. Anything else fails closed.
///
/// The chain POLICY value is deliberately not compared here:
/// rustables 0.9.0's dump decoder maps NF_DROP to ChainPolicy::Accept
/// (chain.rs:75-76, upstream bug), so a live DROP policy can never
/// read back as Drop through this library. Enforcement is proven
/// BEHAVIORALLY instead — [`crate::kill_switch::enforcement_probe`] — which is the
/// stronger check anyway (FR-64/65: the switch must KILL, not merely
/// look like a switch).
pub fn validate(
    policy: &KillSwitchPolicy,
    generation: GenerationId,
) -> Result<(), KillSwitchError> {
    let fail = |message: &str| KillSwitchError::Validation(message.to_owned());
    let table = our_table()?.ok_or_else(|| fail("no protonwire table exists"))?;
    let markers = marker_generations(&table)?;
    if markers != vec![generation] {
        return Err(fail(&format!(
            "marker mismatch: expected [{generation:?}], found {markers:?}"
        )));
    }
    let mut output_found = false;
    for chain in list_chains_for_table(&table)? {
        if chain.get_name().is_some_and(|name| name == OUTPUT_CHAIN) {
            output_found = true;
            let rules = rustables::list_rules_for_chain(&chain)?;
            let count = rules.len();
            if count != expected_rule_count(policy) {
                return Err(fail(&format!(
                    "rule count {count} != the rendered {}",
                    expected_rule_count(policy)
                )));
            }
        }
    }
    if !output_found {
        return Err(fail("the output base chain is missing"));
    }
    Ok(())
}

/// The behavioral enforcement proof (FR-64/65): ONE UDP probe,
/// socket-bound to the UPLINK interface (`SO_BINDTODEVICE`) so its
/// egress is deterministically NON-tunnel — the exact shape of a
/// leak — sent to 192.0.2.1:9 (RFC 5737 TEST-NET-1, unroutable), and
/// required to die at the counted drop. When the switch is enforced
/// the packet dies in the kernel (zero side effects); when it is
/// not, the counter is still and this fails closed. Binding to the
/// uplink is what makes the probe honest: a probe routed through
/// the TUN is tunnel traffic — accepted BY DESIGN — and proves
/// nothing about the kill.
pub fn enforcement_probe(uplink_ifname: &str) -> Result<(), KillSwitchError> {
    let before = dropped_packets()?;
    let probe = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|error| KillSwitchError::Netfilter(error.to_string()))?;
    nix::sys::socket::setsockopt(
        &probe,
        nix::sys::socket::sockopt::BindToDevice,
        &std::ffi::OsString::from(uplink_ifname),
    )
    .map_err(|error| KillSwitchError::Netfilter(format!("SO_BINDTODEVICE: {error}")))?;
    // The send's errno is ambiguous on the bound path: the kernel
    // may surface the DROP itself as EPERM. The counter is the
    // truth — read it whether or not the send errored.
    let _ = probe.send_to(b"pw-enforcement-probe", "192.0.2.1:9");
    let after = dropped_packets()?;
    if after > before {
        Ok(())
    } else {
        Err(KillSwitchError::Validation(
            "the enforcement probe egressed the uplink and was NOT dropped — the kill switch is not enforced".into(),
        ))
    }
}

/// Remove the kill switch — ONLY our table (marker-proven); a
/// lookalike refuses as always.
pub fn remove() -> Result<(), KillSwitchError> {
    let table = our_table()?.ok_or(KillSwitchError::Netfilter("nothing to remove".into()))?;
    let markers = marker_generations(&table)?;
    match decide_live(Some(&markers)) {
        ApplyDecision::RefuseLookalike => Err(KillSwitchError::Lookalike),
        _ => {
            let mut batch = Batch::new();
            batch.add(&table, MsgType::Del);
            batch.send()?;
            Ok(())
        }
    }
}

/// Read back the terminal drop rule's packet counter — the
/// enforcement proof surface (the netns IT).
pub fn dropped_packets() -> Result<u64, KillSwitchError> {
    let table =
        our_table()?.ok_or_else(|| KillSwitchError::Validation("no protonwire table".into()))?;
    for chain in list_chains_for_table(&table)? {
        if !chain.get_name().is_some_and(|name| name == OUTPUT_CHAIN) {
            continue;
        }
        for rule in rustables::list_rules_for_chain(&chain)? {
            let Some(expressions) = rule.get_expressions() else {
                continue;
            };
            for expression in expressions.iter() {
                if let Some(rustables::expr::ExpressionVariant::Counter(counter)) =
                    expression.get_data()
                {
                    // A counter the kernel has not reported yet reads
                    // as unset — zero packets, not an error.
                    return Ok(counter.nb_packets.unwrap_or(0));
                }
            }
        }
    }
    Err(KillSwitchError::Validation(
        "the counted drop rule is missing".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_names_round_trip() {
        for generation in [0, 1, 0xdead_beef, u64::MAX] {
            let name = GenerationId(generation).marker_chain_name();
            assert!(name.starts_with(MARKER_PREFIX), "{name}");
            assert_eq!(
                GenerationId::from_chain_name(&name),
                Some(GenerationId(generation))
            );
        }
    }

    #[test]
    fn non_marker_names_are_not_ours() {
        assert_eq!(GenerationId::from_chain_name("pw-output"), None);
        assert_eq!(GenerationId::from_chain_name("pw-gen-nothex"), None);
        assert_eq!(GenerationId::from_chain_name("pw-gen-"), None);
        assert_eq!(GenerationId::from_chain_name("protonwire"), None);
        assert_eq!(
            GenerationId::from_chain_name("pw-gen-0000000000000001extra"),
            None
        );
    }

    #[test]
    fn apply_decisions_follow_the_live_observation() {
        assert_eq!(decide_live(None), ApplyDecision::FreshApply);
        assert_eq!(
            decide_live(Some(&[GenerationId(7)])),
            ApplyDecision::ReplaceOwned(GenerationId(7))
        );
    }

    #[test]
    fn a_present_table_without_markers_is_a_lookalike() {
        // The live-side contract the IT pins with the kernel: table
        // present + zero markers => RefuseLookalike, never a fresh
        // apply over someone else's table.
        assert_eq!(decide_live(Some(&[])), ApplyDecision::RefuseLookalike);
        assert_eq!(
            decide_live(Some(&[GenerationId(3)])),
            ApplyDecision::ReplaceOwned(GenerationId(3))
        );
    }

    #[test]
    fn the_rendered_rule_count_matches_the_policy() {
        let base = KillSwitchPolicy {
            tun_ifindex: 5,
            allow_dhcp_v4: false,
            lan_ifindex: None,
            bypass_mark: 0x21,
        };
        assert_eq!(expected_rule_count(&base), 4);
        assert_eq!(
            expected_rule_count(&KillSwitchPolicy {
                allow_dhcp_v4: true,
                ..base.clone()
            }),
            5
        );
        assert_eq!(
            expected_rule_count(&KillSwitchPolicy {
                lan_ifindex: Some(9),
                ..base.clone()
            }),
            5
        );
        assert_eq!(
            expected_rule_count(&KillSwitchPolicy {
                allow_dhcp_v4: true,
                lan_ifindex: Some(9),
                ..base
            }),
            6
        );
    }
}
