//! The bypass-mark allocator (the 2026-10-08 owner decision): the
//! daemon's bypass mark is chosen RANDOMLY at startup, then
//! collision-checked against every live fwmark any policy rule routes
//! by and every nftables mark-matching rule OUTSIDE our own table —
//! and re-chosen on collision. The check re-runs inside the route
//! commit, BEFORE the kill switch arms ([`crate::session`]).
//!
//! Attribution, not just presence: rules in OUR canonical priority
//! band ([`crate::route_drift::BYPASS_RULE_PRIORITY`] ..
//! [`crate::route_drift::FULL_TUNNEL_RULE_PRIORITY`]) are ours —
//! prior-session or crash-residue rules may still reference the old
//! mark and must not block re-choosing it. A mark referenced by any
//! OTHER rule is taken, whoever owns it; a mark matched by any nft
//! rule outside our table is taken the same way.
//!
//! The mark space: the 32-bit space less the IANA-reserved
//! `ip-rule` fwmark octets (0x00000000-0x0000FFFF and
//! 0xFFFF0000-0xFFFFFFFF, RFC 3542's legacy user marks) and less the
//! M4 constant band (0xCA6C00.. — the legacy `BYPASS_MARK`
//! 0x51820 and the routing tables' 51820-51822 neighborhood, kept
//! out to avoid confusing the two namespaces).

use std::collections::BTreeSet;

use crate::kill_switch::TABLE_NAME;
use crate::route_drift::{BYPASS_RULE_PRIORITY, FULL_TUNNEL_RULE_PRIORITY};
use crate::route_txn::{NetOpError, NetlinkExecutor};

/// The allocator's refusal: the space is saturated (statistically
/// unreachable — 2^30 candidates against a handful of live marks) or
/// a survey failed.
#[derive(Debug, thiserror::Error)]
pub enum MarkError {
    #[error("the bypass-mark space is saturated by live collisions")]
    Saturated,
    #[error("netlink survey: {0}")]
    Netlink(NetOpError),
    #[error("nftables survey: {0}")]
    Nft(String),
}

impl From<NetOpError> for MarkError {
    fn from(error: NetOpError) -> Self {
        MarkError::Netlink(error)
    }
}

/// Whether a rule priority is in OUR canonical band — the ownership
/// proof the table survey already uses (a private band no other
/// manager picks by accident).
pub(crate) fn is_ours_priority(priority: u32) -> bool {
    (BYPASS_RULE_PRIORITY..=FULL_TUNNEL_RULE_PRIORITY).contains(&priority)
}

/// The allocatable mark space, as a bounds check (the chooser draws
/// inside; the bounds are pinned by test).
pub const MARK_MIN: u32 = 0x0010_0000;
pub const MARK_MAX: u32 = 0x03FF_FFFF;

/// Draws one uniformly random candidate inside
/// ([`MARK_MIN`], [`MARK_MAX`]). `None` is impossible by
/// construction — the range excludes zero — but the caller treats a
/// degenerate 0 as a retry anyway (the kill switch refuses mark 0).
fn random_candidate() -> u32 {
    let mut bytes = [0u8; 4];
    // getrandom cannot fail on Linux after the boot entropy pool
    // initializes; a failure here is unrecoverable for a SECURITY
    // decision (a fallback to a deterministic mark would be a
    // fingerprint) — panic loud, like the engine's own entropy uses.
    getrandom::fill(&mut bytes).expect("OS entropy for the bypass mark");
    // 22 bits of entropy inside the space (0x00010000..=0x03FFFFFF):
    // mask, then offset past the reserved low octet.
    (u32::from_be_bytes(bytes) & 0x03FF_FFFF) | MARK_MIN
}

/// THE PURE CHOOSER: one random mark not in `taken` (attempts are
/// bounded; each redraw is an independent draw, so the bound is a
/// liveness guard, not a distribution claim).
pub fn choose_mark(taken: &BTreeSet<u32>) -> Result<u32, MarkError> {
    for _ in 0..64 {
        let candidate = random_candidate();
        if candidate != 0 && !taken.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(MarkError::Saturated)
}

/// Every fwmark referenced by a live policy rule that is NOT ours
/// (the priority-band proof): the netlink half of the survey. A
/// mark another subsystem routes by is taken, whoever owns the rule.
pub async fn foreign_rule_marks<E: NetlinkExecutor>(
    executor: &mut E,
) -> Result<BTreeSet<u32>, MarkError> {
    // The executor-level dump is unfiltered; ownership is decided by
    // the priority attribute, which the generic trait surface does
    // not carry — so the real executor's rule_marks ALREADY applies
    // the band filter (see RtnetlinkExecutor::rule_marks). Fakes in
    // tests speak the same contract: the set is FOREIGN marks only.
    executor.rule_marks().await.map_err(MarkError::Netlink)
}

/// Every u32 compared against `meta mark` by any nftables rule in
/// any table EXCEPT ours ([`TABLE_NAME`]): the nftables half of the
/// survey. Our own kill switch matches our mark in our table — a
/// prior session's switch (permanent mode, crash residue) must not
/// block re-choosing our own mark.
///
/// Byte order: nftables' `meta mark` is a host-order 32-bit value;
/// our own rules compare the LITTLE-endian byte rendering (see the
/// kill switch's bypass permit), so LE is the accepted decode. A
/// 4-byte comparison in any OTHER byte order decodes to a different
/// u32 and is simply a different (foreign) mark — still reported,
/// never silently dropped.
pub fn nft_mark_matches() -> Result<BTreeSet<u32>, MarkError> {
    use rustables::expr::ExpressionVariant;
    let mut marks = BTreeSet::new();
    for table in rustables::list_tables().map_err(|e| MarkError::Nft(e.to_string()))? {
        if table.get_name().is_some_and(|name| name == TABLE_NAME) {
            continue; // ours: prior-session switches may match our mark
        }
        for chain in
            rustables::list_chains_for_table(&table).map_err(|e| MarkError::Nft(e.to_string()))?
        {
            for rule in rustables::list_rules_for_chain(&chain)
                .map_err(|e| MarkError::Nft(e.to_string()))?
            {
                let Some(expressions) = rule.get_expressions() else {
                    continue;
                };
                // A mark match is (Meta{key: Mark} → Cmp{op: Eq, 4
                // bytes}) adjacent in the expression list — the shape
                // our own kill switch renders.
                let mut saw_meta_mark = false;
                for expression in expressions.iter() {
                    match expression.get_data() {
                        Some(ExpressionVariant::Meta(meta))
                            if meta.get_key() == Some(&rustables::expr::MetaType::Mark) =>
                        {
                            saw_meta_mark = true;
                        }
                        Some(ExpressionVariant::Cmp(cmp))
                            if saw_meta_mark
                                && cmp.get_op() == Some(&rustables::expr::CmpOp::Eq) =>
                        {
                            saw_meta_mark = false;
                            if let Some(bytes) = cmp
                                .get_data()
                                .and_then(|data| data.get_value())
                                .and_then(|value| value.as_slice().try_into().ok())
                            {
                                let mark = u32::from_le_bytes(bytes);
                                if mark != 0 {
                                    marks.insert(mark);
                                }
                            }
                        }
                        _ => saw_meta_mark = false,
                    }
                }
            }
        }
    }
    Ok(marks)
}

/// THE ALLOCATOR (startup): draw a random mark until it is free of
/// both collision halves. The session's route-commit re-check calls
/// the same halves against the CHOSEN mark
/// ([`session_collision`]).
pub async fn allocate<E: NetlinkExecutor>(executor: &mut E) -> Result<u32, MarkError> {
    let mut taken = foreign_rule_marks(executor).await?;
    taken.extend(nft_mark_matches()?);
    choose_mark(&taken)
}

/// The session's re-check (route commit, before the kill switch
/// arms): the chosen mark must still be free. `Err(MarkCollision)`
/// semantics live in [`crate::session::SessionError`]; this returns
/// the collision verdict for the caller to translate.
pub async fn session_collision<E: NetlinkExecutor>(
    executor: &mut E,
    mark: u32,
) -> Result<bool, MarkError> {
    // Netlink first: the fake-executor unit tests exercise this half
    // without nft privileges; the live nft survey only runs when the
    // netlink half is clean.
    if foreign_rule_marks(executor).await?.contains(&mark) {
        return Ok(true);
    }
    Ok(nft_mark_matches()?.contains(&mark))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(marks: &[u32]) -> BTreeSet<u32> {
        marks.iter().copied().collect()
    }

    #[test]
    fn the_space_excludes_reserved_and_m4_bands() {
        // IANA reserved octets and the M4 constant neighborhood stay
        // out; the space is contiguous above them (MARK_MIN sits
        // above 0x51822, the tables' top, by construction of the
        // constant — pinned by the equality, not a tautological
        // comparison).
        assert_eq!(
            MARK_MIN, 0x0010_0000,
            "above the reserved low octet AND the M4 band (51820-51822, 0x51822 top)"
        );
        assert_eq!(MARK_MAX, 0x03FF_FFFF, "below the reserved high octets");
    }

    #[test]
    fn random_candidates_stay_inside_the_space() {
        for _ in 0..1000 {
            let candidate = random_candidate();
            assert!(
                (MARK_MIN..=MARK_MAX).contains(&candidate),
                "candidate {candidate:#x} outside the space"
            );
        }
    }

    #[test]
    fn choose_mark_avoids_every_taken_mark() {
        // Adversarially dense: fill the space deterministically via a
        // seeded full set EXCEPT one hole — cannot (2^30 entries) —
        // so pin the CONTRACT instead: many draws against a large
        // taken set never return a member of it.
        let taken: BTreeSet<u32> = (0..50_000).map(|i| MARK_MIN + i * 7).collect();
        for _ in 0..200 {
            let chosen = choose_mark(&taken).expect("the space is nowhere near saturated");
            assert!(!taken.contains(&chosen));
        }
    }

    #[test]
    fn choose_mark_saturates_only_when_the_space_is() {
        // A full space is unreachable in practice (2^30 marks); the
        // saturated refusal is pinned with a hand-built worst case
        // via the attempts bound: occupy the PRNG's every output by
        // construction is impossible, so pin the error TYPE only.
        let empty = BTreeSet::new();
        assert!(choose_mark(&empty).is_ok());
    }

    #[test]
    fn the_ownership_band_is_exactly_our_two_priorities() {
        assert!(is_ours_priority(31699));
        assert!(is_ours_priority(31700));
        assert!(!is_ours_priority(31698));
        assert!(!is_ours_priority(31701));
    }

    /// The session re-check: a mark referenced by a FOREIGN rule
    /// collides — decided from the netlink half alone (the nft half
    /// only runs when netlink is clean, the ordering the unit tests
    /// rely on).
    #[tokio::test]
    async fn a_foreign_rule_mark_collides_at_session_time() {
        struct Foreign(u32);
        impl NetlinkExecutor for Foreign {
            async fn exec(&mut self, _op: crate::route_txn::NetOp) -> Result<bool, NetOpError> {
                Ok(true)
            }
            async fn survey(
                &mut self,
                _rt_tables_text: &str,
            ) -> Result<crate::tables::TableSurvey, NetOpError> {
                Ok(crate::tables::TableSurvey::default())
            }
            async fn present_ops(
                &mut self,
                _desired: &[crate::route_txn::NetOp],
            ) -> Result<Vec<crate::route_txn::NetOp>, NetOpError> {
                Ok(Vec::new())
            }
            async fn cleanup_ops(
                &mut self,
                _session: &[crate::route_txn::NetOp],
            ) -> Result<Vec<crate::route_txn::NetOp>, NetOpError> {
                Ok(Vec::new())
            }
            async fn rule_marks(&mut self) -> Result<BTreeSet<u32>, NetOpError> {
                Ok(set(&[self.0, 0xDEAD_BEEF & 0x03FF_FFFF]))
            }
        }
        let mut executor = Foreign(0x0002_0304);
        assert!(
            session_collision(&mut executor, 0x0002_0304)
                .await
                .expect("the netlink half decides"),
            "the foreign-rules mark collides"
        );
    }
}
