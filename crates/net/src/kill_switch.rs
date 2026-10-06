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
/// error, never a silent maybe.
///
/// SYNCHRONOUS BY CONTRACT (rust-review #5): every public fn here
/// blocks on netlink dumps and a UDP send — the daemon calls them
/// from spawn_blocking, never directly on a tokio worker (the
/// sibling route_txn module documents its async-runtime contract
/// the same way).
use std::net::IpAddr;

use rustables::expr::{
    Bitwise, Cmp, CmpOp, Counter, HighLevelPayload, IPv4HeaderField, IPv6HeaderField, Immediate,
    Meta, MetaType, NetworkHeaderField, TransportHeaderField, UDPHeaderField, VerdictKind,
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
    /// Permit v4 DHCP bootstrap (nfproto v4 + udp/67) — the active
    /// uplink's lease renewal while the tunnel is down or
    /// establishing.
    pub allow_dhcp_v4: bool,
    /// Validated LAN permits — destination PREFIX + output
    /// interface each (FR-36): interface alone would accept the
    /// entire off-tunnel Internet the uplink routes (the round-1
    /// P1); the prefix is the scope, the interface the path.
    pub lan_permits: Vec<LanPermit>,
    /// The daemon's private bypass mark — only sockets the active
    /// daemon/ProTUN instance marked match (identity, not a
    /// destination allowlist; FR-61).
    pub bypass_mark: u32,
}

/// One LAN access permit: traffic to `dest` leaving via `oif`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanPermit {
    /// The validated local prefix (LAN or link-local).
    pub dest: crate::route_txn::DestPrefix,
    /// The egress interface's kernel index.
    pub oif: u32,
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
    /// The table's marker matches the PERSISTED prior generation —
    /// an OWNED replace (atomic delete+recreate in one batch).
    ReplaceOwned(GenerationId),
    /// Anything else — no table with a record to prove it, a marker
    /// that does not match the record, or MULTIPLE markers — is a
    /// lookalike: refuse, flush nothing, fail closed (FR-59/65; the
    /// round-1 P1: a chain merely NAMED like our marker is not
    /// ownership — names are forgeable; the private persisted record
    /// is the proof).
    RefuseLookalike,
}

/// Decide the apply from the observed nftables state (pure):
/// `None` = no table (fresh, with no prior record required for a
/// FIRST install); `Some(markers)` = the live table's marker chains,
/// which must be EXACTLY the caller's persisted prior generation —
/// zero markers, a mismatched marker, or several markers all refuse.
pub fn decide_live(
    table_markers: Option<&[GenerationId]>,
    persisted_prior: Option<GenerationId>,
) -> ApplyDecision {
    match (table_markers, persisted_prior) {
        (None, _) => ApplyDecision::FreshApply,
        (Some([]), _) => ApplyDecision::RefuseLookalike,
        (Some([marker]), Some(prior)) if *marker == prior => ApplyDecision::ReplaceOwned(*marker),
        _ => ApplyDecision::RefuseLookalike,
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

/// Tables named `protonwire` (nftables identity is family AND name; rustables keeps the family accessor crate-private, so a same-name other-family table is indistinguishable from here). ZERO = no table; ONE = the candidate; MORE = ambiguity, which the caller treats as a lookalike (refuse — never guess). Ownership is NOT this name match: it is the PERSISTED-PRIOR-verified marker; a same-name wrong-family table carries no marker of ours and refuses on its own.
fn tables_named_us() -> Result<Vec<Table>, KillSwitchError> {
    Ok(list_tables()?
        .into_iter()
        .filter(|table| table.get_name().is_some_and(|name| name == TABLE_NAME))
        .collect())
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
/// validation's exact count (FR-64). The count and the render are
/// pinned to each other by an always-run unit (rust-review #4): a
/// future edit to one without the other fails the plain test lane,
/// not only the netns IT.
fn expected_rule_count(policy: &KillSwitchPolicy) -> usize {
    2 /* tun + loopback */
        + usize::from(policy.allow_dhcp_v4)
        + policy.lan_permits.len()
        + 1 /* bypass mark */
        + 1 /* the probe counter (non-terminating) */
        + 1 /* the counted terminal drop */
}

/// The enforcement probe's destination — RFC 5737 TEST-NET-1: no
/// legitimate host traffic targets it, so a counter rule matching
/// exactly this destination attributes its movement to PROBE-shaped
/// packets alone (the shared-counter false-pass, sec-audit F1).
pub const PROBE_DESTINATION: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192, 0, 2, 1);

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
                // FAMILY FIRST (the round-1 P1): an inet chain matches
                // both families — a bare transport match would permit
                // off-tunnel IPv6 UDP to the same port. NFPROTO_IPV4 = 2.
                .with_expr(Meta::new(MetaType::NfProto))
                .with_expr(Cmp::new(CmpOp::Eq, [2_u8]))
                .with_expr(
                    HighLevelPayload::Transport(TransportHeaderField::Udp(UDPHeaderField::Dport))
                        .build(),
                )
                // NETWORK byte order (the round-1 P1): payload-header
                // registers hold wire-order bytes — the little-endian
                // literal matched port 17152 (0x4300), not DHCP's 67.
                .with_expr(Cmp::new(CmpOp::Eq, 67_u16.to_be_bytes()))
                .with_expr(Immediate::new_verdict(VerdictKind::Accept)),
        );
    }
    for permit in &policy.lan_permits {
        rules.push(render_lan_permit(chain, permit)?);
    }
    rules.push(
        Rule::new(chain)?
            .with_expr(Meta::new(MetaType::Mark))
            .with_expr(Cmp::new(CmpOp::Eq, policy.bypass_mark.to_le_bytes()))
            .with_expr(Immediate::new_verdict(VerdictKind::Accept)),
    );
    // THE PROBE COUNTER, non-terminating, immediately before the
    // terminal drop (sec-audit F1 + the round-2 P1): a counter rule
    // matching exactly the probe's identity (nfproto v4 + the
    // TEST-NET-1 destination) counts PROBE-shaped packets only — the
    // terminal drop's shared counter could false-pass on a noisy
    // host, where unrelated blocked traffic moves it inside the
    // probe's dump window. No verdict: matched packets fall through
    // to the terminal drop (that fall-through IS the enforcement).
    rules.push(
        Rule::new(chain)?
            .with_expr(Meta::new(MetaType::NfProto))
            .with_expr(Cmp::new(CmpOp::Eq, [2_u8]))
            .with_expr(
                HighLevelPayload::Network(NetworkHeaderField::IPv4(IPv4HeaderField::Daddr)).build(),
            )
            .with_expr(Cmp::new(CmpOp::Eq, PROBE_DESTINATION.octets()))
            .with_expr(Counter::default()),
    );
    rules.push(
        Rule::new(chain)?
            .with_expr(Counter::default())
            .with_expr(Immediate::new_verdict(VerdictKind::Drop)),
    );
    Ok(rules)
}

/// One validated LAN permit: destination PREFIX + output interface.
/// Interface alone would accept EVERYTHING that interface routes —
/// enabling LAN access must not open the whole off-tunnel Internet
/// through the uplink (the round-1 P1).
fn render_lan_permit(chain: &Chain, permit: &LanPermit) -> Result<Rule, KillSwitchError> {
    let mask_len = {
        let probe = prefix_mask(permit.dest);
        probe.len()
    };
    let mask = prefix_mask(permit.dest);
    let network = network_address(permit.dest);
    let mut rule = Rule::new(chain)?
        .with_expr(Meta::new(MetaType::Oif))
        .with_expr(Cmp::new(CmpOp::Eq, permit.oif.to_le_bytes()));
    rule = match permit.dest.addr {
        IpAddr::V4(_) => rule
            .with_expr(Meta::new(MetaType::NfProto))
            .with_expr(Cmp::new(CmpOp::Eq, [2_u8]))
            .with_expr(
                HighLevelPayload::Network(NetworkHeaderField::IPv4(IPv4HeaderField::Daddr)).build(),
            ),
        IpAddr::V6(_) => rule
            .with_expr(Meta::new(MetaType::NfProto))
            .with_expr(Cmp::new(CmpOp::Eq, [10_u8]))
            .with_expr(
                HighLevelPayload::Network(NetworkHeaderField::IPv6(IPv6HeaderField::Daddr)).build(),
            ),
    };
    Ok(rule
        .with_expr(Bitwise::new(mask, vec![0_u8; mask_len]).map_err(
            |error: rustables::error::BuilderError| {
                KillSwitchError::Netfilter(format!("lan mask: {error}"))
            },
        )?)
        .with_expr(Cmp::new(CmpOp::Eq, network))
        .with_expr(Immediate::new_verdict(VerdictKind::Accept)))
}

/// The wire-order netmask for a prefix (big-endian bytes, host bits
/// zero).
fn prefix_mask(dest: crate::route_txn::DestPrefix) -> Vec<u8> {
    let (bytes, len) = match dest.addr {
        IpAddr::V4(addr) => (addr.octets().to_vec(), dest.len as u32),
        IpAddr::V6(addr) => (addr.octets().to_vec(), dest.len as u32),
    };
    bytes
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let bit = index as u32 * 8;
            match len.saturating_sub(bit) {
                0 => 0,
                covered if covered >= 8 => 0xff,
                covered => 0xff_u8 << (8 - covered),
            }
        })
        .collect()
}

/// The wire-order network address for a prefix (host bits zeroed).
fn network_address(dest: crate::route_txn::DestPrefix) -> Vec<u8> {
    let mask = prefix_mask(dest);
    let bytes = match dest.addr {
        IpAddr::V4(addr) => addr.octets().to_vec(),
        IpAddr::V6(addr) => addr.octets().to_vec(),
    };
    bytes.iter().zip(&mask).map(|(byte, m)| byte & m).collect()
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
    persisted_prior: Option<GenerationId>,
) -> Result<(), KillSwitchError> {
    // A ZERO bypass mark is a config error, not a disabled feature
    // (the round-2 P1 + sec-audit F3 + rust-review #2): mark==0
    // matches every UNMARKED packet — the entire non-VPN population
    // — and the switch silently accepts everything it exists to
    // drop. route_drift's 0-disables convention belongs to the
    // ROUTING side only; the kill switch requires the real mark.
    if policy.bypass_mark == 0 {
        return Err(KillSwitchError::Validation(
            "bypass_mark is zero — `meta mark 0 accept` would match every unmarked packet \
             and hollow the kill switch (FR-61); pass the daemon's real mark"
                .into(),
        ));
    }
    // LAN permits carry real prefixes (rust-review #3): a /0 permit
    // is interface-only (the round-1 shape), an over-wide length
    // silently clamps to host-route semantics — both refuse here,
    // at the last line before the kernel.
    for permit in &policy.lan_permits {
        let width = match permit.dest.addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if permit.dest.len == 0 || permit.dest.len > width {
            return Err(KillSwitchError::Validation(format!(
                "LAN permit {}/{} is not a usable prefix (width {width}) — a /0 permit is \
                 interface-only and an over-wide length silently clamps",
                permit.dest.addr, permit.dest.len
            )));
        }
    }
    let tun_ifindex = iface_index(tun_ifname)
        .map_err(|_| KillSwitchError::MissingInterface(tun_ifname.to_owned()))?
        as u32;
    let policy = KillSwitchPolicy {
        tun_ifindex,
        ..policy.clone()
    };

    let named = tables_named_us()?;
    if named.len() > 1 {
        return Err(KillSwitchError::Lookalike);
    }
    let existing = named.into_iter().next();
    let markers = match &existing {
        Some(table) => marker_generations(table)?,
        None => Vec::new(),
    };
    match decide_live(
        existing.as_ref().map(|_| markers.as_slice()),
        persisted_prior,
    ) {
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
    let named = tables_named_us()?;
    if named.len() > 1 {
        return Err(fail("multiple protonwire tables — ambiguous, refusing"));
    }
    let table = named
        .into_iter()
        .next()
        .ok_or_else(|| fail("no protonwire table exists"))?;
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
pub fn remove(persisted_prior: Option<GenerationId>) -> Result<(), KillSwitchError> {
    let named = tables_named_us()?;
    if named.len() > 1 {
        return Err(KillSwitchError::Lookalike);
    }
    // Idempotent no-table (rust-review #9): a disconnect after a
    // connect that failed before apply — or after someone else's
    // cleanup — is SUCCESS, matching the idempotent-delete
    // philosophy everywhere else in the stack.
    let Some(table) = named.into_iter().next() else {
        return Ok(());
    };
    let markers = marker_generations(&table)?;
    match decide_live(Some(&markers), persisted_prior) {
        ApplyDecision::RefuseLookalike => Err(KillSwitchError::Lookalike),
        _ => {
            let mut batch = Batch::new();
            batch.add(&table, MsgType::Del);
            batch.send()?;
            Ok(())
        }
    }
}

/// Read back the PROBE counter rule's packet count — the
/// enforcement proof surface. This is NOT the terminal drop's
/// counter: the probe rule matches only the probe's identity
/// (nfproto v4 + TEST-NET-1 destination), so its movement attributes
/// to probe-shaped packets alone; the shared terminal counter could
/// false-pass on a noisy host (sec-audit F1). Multiple same-named
/// tables are an AMBIGUOUS evidence source — refuse (sec-audit F5).
pub fn dropped_packets() -> Result<u64, KillSwitchError> {
    let named = tables_named_us()?;
    if named.len() > 1 {
        return Err(KillSwitchError::Validation(
            "multiple protonwire tables — ambiguous evidence".into(),
        ));
    }
    let table = named
        .into_iter()
        .next()
        .ok_or_else(|| KillSwitchError::Validation("no protonwire table".into()))?;
    for chain in list_chains_for_table(&table)? {
        if !chain.get_name().is_some_and(|name| name == OUTPUT_CHAIN) {
            continue;
        }
        for rule in rustables::list_rules_for_chain(&chain)? {
            let Some(expressions) = rule.get_expressions() else {
                continue;
            };
            // THE PROBE RULE carries a counter and NO verdict (the
            // terminal drop carries counter + Drop) — first-wins on
            // any counter would misattribute to a permit rule the
            // day one grows a counter (rust-review #4).
            let has_verdict = expressions.iter().any(|expression| {
                matches!(
                    expression.get_data(),
                    Some(rustables::expr::ExpressionVariant::Immediate(_))
                )
            });
            if has_verdict {
                continue;
            }
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
        "the probe counter rule is missing".into(),
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
        assert_eq!(decide_live(None, None), ApplyDecision::FreshApply);
        assert_eq!(
            decide_live(Some(&[GenerationId(7)]), Some(GenerationId(7))),
            ApplyDecision::ReplaceOwned(GenerationId(7))
        );
        // A marker WITHOUT the caller's matching record is a
        // lookalike — names are forgeable; the private record is the
        // proof (the round-1 P1).
        assert_eq!(
            decide_live(Some(&[GenerationId(7)]), None),
            ApplyDecision::RefuseLookalike
        );
        assert_eq!(
            decide_live(Some(&[GenerationId(7)]), Some(GenerationId(6))),
            ApplyDecision::RefuseLookalike
        );
        // Multiple markers are ambiguous — refuse.
        assert_eq!(
            decide_live(
                Some(&[GenerationId(7), GenerationId(8)]),
                Some(GenerationId(7))
            ),
            ApplyDecision::RefuseLookalike
        );
    }

    #[test]
    fn a_present_table_without_markers_is_a_lookalike() {
        // The live-side contract the IT pins with the kernel: table
        // present + zero markers => RefuseLookalike, never a fresh
        // apply over someone else's table.
        assert_eq!(
            decide_live(Some(&[]), Some(GenerationId(3))),
            ApplyDecision::RefuseLookalike
        );
        assert_eq!(
            decide_live(Some(&[GenerationId(3)]), Some(GenerationId(3))),
            ApplyDecision::ReplaceOwned(GenerationId(3))
        );
    }

    fn lan(dest_addr: &str, len: u8, oif: u32) -> LanPermit {
        LanPermit {
            dest: crate::route_txn::DestPrefix {
                addr: dest_addr.parse().unwrap(),
                len,
            },
            oif,
        }
    }

    #[test]
    fn the_rendered_rule_count_matches_the_policy() {
        let base = KillSwitchPolicy {
            tun_ifindex: 5,
            allow_dhcp_v4: false,
            lan_permits: Vec::new(),
            bypass_mark: 0x21,
        };
        assert_eq!(expected_rule_count(&base), 5);
        assert_eq!(
            expected_rule_count(&KillSwitchPolicy {
                allow_dhcp_v4: true,
                ..base.clone()
            }),
            6
        );
        assert_eq!(
            expected_rule_count(&KillSwitchPolicy {
                lan_permits: vec![lan("192.168.1.0", 24, 9)],
                ..base.clone()
            }),
            6
        );
        assert_eq!(
            expected_rule_count(&KillSwitchPolicy {
                allow_dhcp_v4: true,
                lan_permits: vec![lan("192.168.1.0", 24, 9), lan("fe80::", 10, 9)],
                ..base
            }),
            8
        );
    }

    #[test]
    fn the_rendered_rules_count_matches_offline() {
        // rust-review #4: the literals above and the RENDER must
        // co-vary in the always-run lane — only iface_index(lo)
        // touches the system, which every Linux test host has.
        let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME);
        let chain = Chain::new(&table).with_name(OUTPUT_CHAIN);
        for policy in [
            KillSwitchPolicy {
                tun_ifindex: 5,
                allow_dhcp_v4: false,
                lan_permits: Vec::new(),
                bypass_mark: 0x21,
            },
            KillSwitchPolicy {
                tun_ifindex: 5,
                allow_dhcp_v4: true,
                lan_permits: vec![lan("192.168.1.0", 24, 9)],
                bypass_mark: 0x21,
            },
        ] {
            let rendered = render_rules(&chain, &policy).expect("offline render");
            assert_eq!(
                rendered.len(),
                expected_rule_count(&policy),
                "render and count drifted for {policy:?}"
            );
        }
    }

    #[test]
    fn a_zero_bypass_mark_is_refused() {
        // The round-2 P1: mark 0 would accept every UNMARKED packet.
        let policy = KillSwitchPolicy {
            tun_ifindex: 1,
            allow_dhcp_v4: false,
            lan_permits: Vec::new(),
            bypass_mark: 0,
        };
        let refusal = apply("lo", "lo", &policy, GenerationId(1), None)
            .expect_err("zero mark refuses before any netfilter work");
        assert!(
            matches!(refusal, KillSwitchError::Validation(_)),
            "{refusal:?}"
        );
    }

    #[test]
    fn unusable_lan_prefixes_are_refused() {
        for dest in [
            crate::route_txn::DestPrefix {
                addr: "0.0.0.0".parse().unwrap(),
                len: 0,
            },
            crate::route_txn::DestPrefix {
                addr: "10.1.0.0".parse().unwrap(),
                len: 33,
            },
        ] {
            let policy = KillSwitchPolicy {
                tun_ifindex: 1,
                allow_dhcp_v4: false,
                lan_permits: vec![LanPermit { dest, oif: 9 }],
                bypass_mark: 0x21,
            };
            let refusal = apply("lo", "lo", &policy, GenerationId(1), None)
                .expect_err("unusable prefix refuses");
            assert!(
                matches!(refusal, KillSwitchError::Validation(_)),
                "{refusal:?}"
            );
        }
    }

    #[test]
    fn lan_masks_and_networks_are_wire_order() {
        let dest = crate::route_txn::DestPrefix {
            addr: "192.168.5.130".parse().unwrap(),
            len: 24,
        };
        assert_eq!(prefix_mask(dest), vec![255, 255, 255, 0]);
        assert_eq!(network_address(dest), vec![192, 168, 5, 0]);
        let dest = crate::route_txn::DestPrefix {
            addr: "fe80::1".parse().unwrap(),
            len: 10,
        };
        let mask = prefix_mask(dest);
        assert_eq!(mask[..2], [0xff, 0xc0]);
        assert_eq!(network_address(dest)[..2], [0xfe, 0x80]);
    }
}
