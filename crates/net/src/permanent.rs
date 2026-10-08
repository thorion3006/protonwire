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
pub fn render_early_unit() -> String {
    format!(
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
ExecStart={binary} early-firewall apply
RemainAfterExit=yes
# The early unit must survive daemon crashes: it writes the
# nftables rules directly, not through the main daemon's socket.
ExecStop={binary} early-firewall remove

[Install]
WantedBy=network-pre.target
"#,
        binary = "protonwire-early-firewall"
    )
}

/// Apply the EARLY kill switch: a minimal drop-all (no TUN — there
/// is none at boot; no routes — there are none yet). The TUN
/// permit is absent, so ALL output dies until the daemon connects.
pub fn apply_early_firewall(generation: GenerationId) -> Result<(), KillSwitchError> {
    let policy = KillSwitchPolicy {
        tun_ifindex: 0, // No TUN at boot — the oif==0 permit matches nothing
        allow_dhcp_v4: false,
        lan_permits: Vec::new(),
        bypass_mark: 0x1, // A nonzero mark (the zero-mark refusal is in apply)
    };
    // The "uplink" for the enforcement probe: at boot there may be
    // no uplink. The probe still works (SO_BINDTODEVICE on a
    // nonexistent interface gives an error, but the switch is
    // proven by the ruleset dump in validate). Use "lo" as the
    // probe target — loopback is always present.
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
        assert!(unit.contains("WantedBy=network-pre.target"));
        assert!(unit.contains("DO NOT EDIT"));
    }

    #[test]
    fn early_unit_names_the_binary() {
        let unit = render_early_unit();
        assert!(unit.contains("protonwire-early-firewall"));
    }
}
