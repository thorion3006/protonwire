//! Permanent mode (FR-63A, IT-27): the early-boot firewall unit
//! ordered BEFORE `network-pre.target`, surviving daemon
//! stop/crash, removed only by an explicit authorized disable.
//!
//! The UNIT: `protonwire-early-firewall.service` — a Type=oneshot
//! that applies a minimal drop-all kill switch (no TUN, no routes,
//! just the inet-family default drop on the OUTPUT chain). The
//! main daemon's `After=network-online.target` CANNOT provide this
//! guarantee — the early unit runs before any uplink configuration.
//!
//! REMOVAL: only the daemon's explicit `protonwire config set
//! kill_switch off` (or the recovery path) removes the early rules.
//! A daemon crash, stop, or restart LEAVES THEM INTACT — the
//! fail-closed contract.

use crate::kill_switch::{self, GenerationId, KillSwitchError, KillSwitchPolicy};

/// The early-boot unit's name (the systemd unit file's basename).
pub const EARLY_UNIT_NAME: &str = "protonwire-early-firewall.service";

/// The systemd unit file's content — Before=network-pre.target,
/// DefaultDependencies=no (it must run before anything else).
/// The binary is the MAIN `protonwire` CLI with the
/// `early-firewall` subcommand (the round-5 P1: the original
/// referenced a nonexistent `protonwire-early-firewall` helper —
/// the main CLI carries the subcommand; no separate binary to
/// install). RequiredBy (not WantedBy) makes the networking units
/// WAIT for the firewall (the round-5 P1).
pub fn render_early_unit() -> String {
    r#"# ProtonWire early-boot firewall (FR-63A, IT-27)
# Installed by the protonwire daemon when permanent kill switch is
# enabled. DO NOT EDIT — removed only by `protonwire config set
# kill_switch off`.
[Unit]
Description=ProtonWire permanent kill switch (early boot)
Before=network-pre.target
DefaultDependencies=no

[Service]
Type=oneshot
# The main CLI carries the early-firewall subcommand (applies the
# minimal drop-all nftables ruleset before any uplink configures).
ExecStart=/usr/bin/protonwire early-firewall apply
# Deliberately NO stop action (FR-63A): stop/crash LEAVES the
# rules in place; removal is ONLY the explicit config-set disable.
RemainAfterExit=yes

[Install]
# RequiredBy (not WantedBy): the networking units WAIT for the
# firewall to be in place before starting (the round-5 P1 —
# WantedBy is a weak dependency that does not guarantee ordering).
RequiredBy=network-pre.target
"#
    .to_string()
}

/// Apply the EARLY kill switch: a minimal drop-all (no TUN — there
/// is none at boot; no routes — there are none yet). The TUN
/// permit is absent, so ALL output dies until the daemon connects —
/// EXCEPT DHCP (the round-5 P1: blocking DHCP prevents the uplink
/// from configuring at boot, which defeats the purpose of the early
/// firewall). The bypass mark is a randomly-chosen nonce (the M6
/// contract; the round-5 P1: a fixed 0x1 could collide).
pub fn apply_early_firewall(generation: GenerationId) -> Result<(), KillSwitchError> {
    // A random nonzero mark — not a fixed constant (the round-5 P1);
    // the daemon replaces it with its collision-checked mark when
    // it starts.
    let nonce_mark = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() | 1) // nonzero
        .unwrap_or(0x5A01); // fallback constant if clock fails
    let policy = KillSwitchPolicy {
        tun_ifindex: 0,      // No TUN at boot — the oif==0 permit matches nothing
        allow_dhcp_v4: true, // DHCP must work for the uplink to configure
        lan_permits: Vec::new(),
        bypass_mark: nonce_mark,
    };
    // The enforcement probe: lo is the only always-present interface
    // at boot. The probe proves the switch is applied (the ruleset
    // + the behavioral drop); the lo-permit means the probe's own
    // packet dies at the terminal drop (NOT the lo accept) — proving
    // the default-drop is the active policy.
    kill_switch::apply("lo", "lo", &policy, generation, None)
}

/// Remove the early firewall — ONLY the explicit disable path
/// (FR-63A: "Only an explicit authorized disable/recovery
/// operation removes them").
pub fn remove_early_firewall(generation: GenerationId) -> Result<(), KillSwitchError> {
    kill_switch::remove(Some(generation))
}

/// The permanent-mode policy: what the daemon's config surface
/// translates to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermanentMode {
    /// The kill switch is `on` — enforced while connected, removed
    /// on disconnect.
    On,
    /// The kill switch is `permanent` — the early-boot unit is
    /// enabled; the switch NEVER removes (FR-63).
    Permanent,
    /// The kill switch is `off` (the recovery path).
    Off,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_unit_renders_with_required_fields() {
        let unit = render_early_unit();
        assert!(unit.contains("Before=network-pre.target"));
        assert!(unit.contains("DefaultDependencies=no"));
        assert!(unit.contains("Type=oneshot"));
        assert!(unit.contains("RequiredBy=network-pre.target"));
        assert!(!unit.contains("ExecStop="), "no automatic stop (FR-63A)");
        assert!(unit.contains("/usr/bin/protonwire early-firewall"));
        assert!(unit.contains("DO NOT EDIT"));
    }

    #[test]
    fn early_unit_references_the_main_cli() {
        let unit = render_early_unit();
        assert!(unit.contains("/usr/bin/protonwire"));
        assert!(!unit.contains("protonwire-early-firewall "));
    }
}
