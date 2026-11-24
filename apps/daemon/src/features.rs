//! The LocalAgent feature posture (M6 slice 2): the daemon's `features`
//! config section as the engine's agent request, the per-connection
//! modifier overlay (PRD 9.3's `--netshield` / `--nat` /
//! `--vpn-accelerator`), and T-18's incompatibility rules — validated
//! on the EFFECTIVE set so an impossible combination is refused typed,
//! never silently changed (DoD item 10).
//!
//! Two pure functions, no I/O: [`posture`] maps the config at startup
//! (a config-level conflict refuses daemon startup — the strict-load
//! philosophy), and [`resolve`] overlays one connection's modifiers on
//! that posture and re-validates the result. The rules:
//!
//! - **Port forwarding × Moderate NAT** (FR, T-18): moderate NAT breaks
//!   the NAT-PMP mapping — refused whichever side names it.
//! - **Custom DNS × NetShield** (FR-49A): NetShield needs Proton's
//!   filtering DNS; `netshield off` resolves the conflict the user's
//!   way, any other level beside `dns.mode: custom` refuses.
//! - **Port forwarding entitlement** (FR-7, paid-only): refused unless
//!   the account's entitlement PROVES the paid plan — no snapshot is a
//!   refusal too (the standing fail-closed rule: never guess a tier).
//!   Only composed when port forwarding is effectively on, so the
//!   default path never waits on an entitlement read.
//!
//! NetShield's account allowance is deliberately NOT gated here: FR-53
//! says an unsupported mode FAILS GRACEFULLY, and the LocalAgent's
//! own refusal is the precise, authoritative answer — surfaced through
//! the T-20 ledger and the T-39 status block (FR-54) rather than a
//! guessed pre-connect refusal.

use protonwire_frontend_api::{ConnectModifiers, NatMode, NetshieldLevel};
use protonwire_protocol::engine::{EngineAgentSettings, EngineNetshield};
use protonwire_store::config::{DnsMode, NetShieldLevel, SystemConfig};

/// Whether the account is known to hold the plan port forwarding
/// requires (FR-7: paid-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortForwardingEntitlement {
    /// Not composed — the startup posture has no account yet; the
    /// connect path owns this check.
    Unchecked,
    /// The entitlement snapshot answered: paid, or not.
    Known(bool),
    /// No usable snapshot. A refusal: an installed adapter's tier is
    /// never guessed, and an uninstalled one proves nothing.
    Unknown,
}

/// A refused feature set. Every variant is one of T-18's rules.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeaturesError {
    /// Port forwarding × Moderate NAT.
    #[error(
        "moderate NAT is incompatible with port forwarding (T-18: moderate NAT breaks the \
         NAT-PMP mapping — disable one)"
    )]
    NatPortForwardingConflict,
    /// Custom DNS × NetShield (FR-49A).
    #[error(
        "NetShield requires Proton's filtering DNS — it is incompatible with dns.mode=custom \
         (FR-49A); set netshield off or dns.mode proton"
    )]
    NetShieldCustomDnsConflict,
    /// Port forwarding without the paid plan.
    #[error(
        "port forwarding requires a paid plan and the account's entitlement does not include \
         it (FR-7) — disable features.port_forwarding"
    )]
    PortForwardingNotEntitled,
    /// Port forwarding with no verifiable entitlement (fail closed).
    #[error(
        "port forwarding requires a paid plan and the account's entitlement cannot be verified \
         (no entitlement snapshot) — retry once signed in, or disable features.port_forwarding"
    )]
    PortForwardingEntitlementUnknown,
}

impl FeaturesError {
    /// The wire code: an impossible COMBINATION is the caller's
    /// parameters; a missing plan is the account's.
    pub fn to_rpc(&self) -> protonwire_frontend_api::RpcError {
        use protonwire_frontend_api::{RpcError, RpcErrorCode};
        let code = match self {
            Self::NatPortForwardingConflict | Self::NetShieldCustomDnsConflict => {
                RpcErrorCode::InvalidParams
            }
            Self::PortForwardingNotEntitled | Self::PortForwardingEntitlementUnknown => {
                RpcErrorCode::EntitlementMissing
            }
        };
        RpcError::new(code, self.to_string())
    }
}

/// The engine's NetShield level off the wire's (1:1).
fn netshield_from_wire(level: NetshieldLevel) -> EngineNetshield {
    match level {
        NetshieldLevel::Off => EngineNetshield::None,
        NetshieldLevel::Malware => EngineNetshield::MalwareFilter,
        NetshieldLevel::AdsTrackersMalware => EngineNetshield::AdsAndMalwareFilter,
        NetshieldLevel::AdultAdsTrackersMalware => EngineNetshield::AdultAndAdsAndMalwareFilter,
    }
}

/// The configured posture: the `features` section as the agent request.
/// A config-level incompatibility REFUSES (startup fails with the
/// message naming both knobs) — the same rules [`resolve`] applies to
/// a single connection, so no invalid posture ever reaches the agent.
pub fn posture(config: &SystemConfig) -> Result<EngineAgentSettings, FeaturesError> {
    let netshield_level = match config.features.netshield {
        NetShieldLevel::Off => EngineNetshield::None,
        NetShieldLevel::Malware => EngineNetshield::MalwareFilter,
        NetShieldLevel::AdsTrackersMalware => EngineNetshield::AdsAndMalwareFilter,
        NetShieldLevel::AdultAdsTrackersMalware => EngineNetshield::AdultAndAdsAndMalwareFilter,
    };
    let settings = EngineAgentSettings {
        netshield_level: Some(netshield_level),
        split_tcp: Some(config.features.vpn_accelerator),
        random_nat: Some(config.features.nat == protonwire_store::config::NatMode::Moderate),
        port_forwarding: Some(config.features.port_forwarding),
        ..Default::default()
    };
    // Entitlements are the connect path's: startup has no account.
    validate(
        &settings,
        config.dns.mode,
        PortForwardingEntitlement::Unchecked,
    )?;
    Ok(settings)
}

/// THIS connection's agent request: the configured posture with the
/// per-connection modifiers overlaid (an explicit knob wins; `None`
/// keeps the configured value), re-validated as a whole — a modifier
/// that conflicts with a CONFIGURED knob refuses exactly as a
/// config-level conflict would.
pub fn resolve(
    base: EngineAgentSettings,
    modifiers: Option<&ConnectModifiers>,
    dns_mode: DnsMode,
    port_forwarding: PortForwardingEntitlement,
) -> Result<EngineAgentSettings, FeaturesError> {
    let mut effective = base;
    if let Some(modifiers) = modifiers {
        if let Some(level) = modifiers.netshield {
            effective.netshield_level = Some(netshield_from_wire(level));
        }
        if let Some(nat) = modifiers.nat {
            effective.random_nat = Some(nat == NatMode::Moderate);
        }
        if let Some(vpn_accelerator) = modifiers.vpn_accelerator {
            effective.split_tcp = Some(vpn_accelerator);
        }
    }
    // FAIL-CLOSED GUARD (the slice-2 rust gate's P3): the connect path
    // must compose a real entitlement answer before an effective PF-on
    // validates — `Unchecked` here would pass fail-OPEN through the
    // permissive startup arm. ConnectModifiers carries no PF knob
    // today, so this is unreachable; the assert pins the contract for
    // the day one exists (the reviewer's exact scenario).
    debug_assert!(
        effective.port_forwarding != Some(true)
            || port_forwarding != PortForwardingEntitlement::Unchecked,
        "resolve() with PF-on requires a composed entitlement — never Unchecked"
    );
    validate(&effective, dns_mode, port_forwarding)?;
    Ok(effective)
}

/// T-18 on an effective set. Pure over the three inputs the rules
/// need — no I/O, no account reads.
///
/// The FAIL-CLOSED GUARD lives in [`resolve`], not here: `Unchecked`
/// is lawful from [`posture`] (startup has no account to compose),
/// but the connect path must present a composed answer whenever the
/// effective set turns PF on — `resolve` debug-asserts that contract.
fn validate(
    settings: &EngineAgentSettings,
    dns_mode: DnsMode,
    port_forwarding: PortForwardingEntitlement,
) -> Result<(), FeaturesError> {
    if settings.random_nat == Some(true) && settings.port_forwarding == Some(true) {
        return Err(FeaturesError::NatPortForwardingConflict);
    }
    if dns_mode == DnsMode::Custom
        && settings
            .netshield_level
            .is_some_and(|level| level != EngineNetshield::None)
    {
        return Err(FeaturesError::NetShieldCustomDnsConflict);
    }
    if settings.port_forwarding == Some(true) {
        match port_forwarding {
            PortForwardingEntitlement::Unchecked => {}
            PortForwardingEntitlement::Known(true) => {}
            PortForwardingEntitlement::Known(false) => {
                return Err(FeaturesError::PortForwardingNotEntitled);
            }
            PortForwardingEntitlement::Unknown => {
                return Err(FeaturesError::PortForwardingEntitlementUnknown);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative configured posture: NetShield on, accelerator
    /// on, strict NAT, no port forwarding (the shipped defaults).
    fn base() -> EngineAgentSettings {
        posture(&SystemConfig::default()).expect("the shipped defaults are a valid posture")
    }

    fn modifier(
        netshield: Option<NetshieldLevel>,
        nat: Option<NatMode>,
        vpn_accelerator: Option<bool>,
    ) -> ConnectModifiers {
        ConnectModifiers {
            netshield,
            nat,
            vpn_accelerator,
        }
    }

    #[test]
    fn posture_maps_every_knob_and_is_the_shipped_default() {
        let settings = base();
        assert_eq!(
            settings.netshield_level,
            Some(EngineNetshield::AdsAndMalwareFilter)
        );
        assert_eq!(settings.split_tcp, Some(true));
        assert_eq!(settings.random_nat, Some(false));
        assert_eq!(settings.port_forwarding, Some(false));
        // Nothing else is requested (no preference — T-20's rule).
        assert_eq!(settings.soft_jail, None);
        assert_eq!(settings.circumvention_routing, None);
        // Every configured NetShield level maps.
        let mut config = SystemConfig::default();
        for (configured, engine) in [
            (NetShieldLevel::Off, EngineNetshield::None),
            (NetShieldLevel::Malware, EngineNetshield::MalwareFilter),
            (
                NetShieldLevel::AdsTrackersMalware,
                EngineNetshield::AdsAndMalwareFilter,
            ),
            (
                NetShieldLevel::AdultAdsTrackersMalware,
                EngineNetshield::AdultAndAdsAndMalwareFilter,
            ),
        ] {
            config.features.netshield = configured;
            assert_eq!(
                posture(&config).unwrap().netshield_level,
                Some(engine),
                "{configured:?}"
            );
        }
    }

    /// T-18 (config level): a config that names BOTH moderate NAT and
    /// port forwarding refuses startup, naming the rule — and either
    /// side alone is a valid posture.
    #[test]
    fn t18_the_config_level_nat_pf_conflict_refuses_startup() {
        let mut config = SystemConfig::default();
        config.features.nat = protonwire_store::config::NatMode::Moderate;
        config.features.port_forwarding = true;
        let error = posture(&config).expect_err("the conflict refuses");
        assert_eq!(error, FeaturesError::NatPortForwardingConflict);
        assert!(
            error.to_string().contains("moderate NAT")
                && error.to_string().contains("port forwarding"),
            "the refusal names both sides: {error}"
        );
        config.features.port_forwarding = false;
        assert_eq!(posture(&config).unwrap().random_nat, Some(true));
        config.features.nat = protonwire_store::config::NatMode::Strict;
        config.features.port_forwarding = true;
        // Port forwarding ALONE is a valid posture at startup — its
        // entitlement is the connect path's check, not startup's.
        assert_eq!(posture(&config).unwrap().port_forwarding, Some(true));
    }

    /// A modifier overrides ONLY its own knob: the configured values
    /// of every other knob survive untouched.
    #[test]
    fn modifiers_override_their_own_knobs_only() {
        let settings = resolve(
            base(),
            Some(&modifier(Some(NetshieldLevel::Off), None, Some(false))),
            DnsMode::Proton,
            PortForwardingEntitlement::Unchecked,
        )
        .unwrap();
        assert_eq!(settings.netshield_level, Some(EngineNetshield::None));
        assert_eq!(settings.split_tcp, Some(false));
        // The untouched knob keeps the configured value.
        assert_eq!(settings.random_nat, Some(false));

        let settings = resolve(
            base(),
            Some(&modifier(None, Some(NatMode::Moderate), None)),
            DnsMode::Proton,
            PortForwardingEntitlement::Unchecked,
        )
        .unwrap();
        assert_eq!(settings.random_nat, Some(true));
        assert_eq!(
            settings.netshield_level,
            Some(EngineNetshield::AdsAndMalwareFilter)
        );
        assert_eq!(settings.split_tcp, Some(true));

        // The FULL NetShield modifier matrix (the qa gate's mutation 1):
        // every wire level maps to its exact engine level — a swap
        // between Malware and AdsTrackersMalware must fail here, not
        // ride the agent handshake as a wrong filtering level.
        for (wire, engine) in [
            (NetshieldLevel::Off, EngineNetshield::None),
            (NetshieldLevel::Malware, EngineNetshield::MalwareFilter),
            (
                NetshieldLevel::AdsTrackersMalware,
                EngineNetshield::AdsAndMalwareFilter,
            ),
            (
                NetshieldLevel::AdultAdsTrackersMalware,
                EngineNetshield::AdultAndAdsAndMalwareFilter,
            ),
        ] {
            let settings = resolve(
                base(),
                Some(&modifier(Some(wire), None, None)),
                DnsMode::Proton,
                PortForwardingEntitlement::Unchecked,
            )
            .unwrap();
            assert_eq!(settings.netshield_level, Some(engine), "{wire:?}");
        }

        // No modifiers, an absent set, and an all-`None` set are the
        // configured posture, field for field.
        for modifiers in [None, Some(ConnectModifiers::default())] {
            assert_eq!(
                resolve(
                    base(),
                    modifiers.as_ref(),
                    DnsMode::Proton,
                    PortForwardingEntitlement::Unchecked
                )
                .unwrap(),
                base()
            );
        }
    }

    /// T-18 (modifier level): `--nat moderate` against a config that
    /// enables port forwarding refuses — the modifier never silently
    /// switches port forwarding off, and it never reaches the agent
    /// half-negotiated.
    #[test]
    fn t18_a_moderate_nat_modifier_against_configured_pf_refuses() {
        let mut config = SystemConfig::default();
        config.features.port_forwarding = true;
        let pf_posture = posture(&config).unwrap();
        let error = resolve(
            pf_posture,
            Some(&modifier(None, Some(NatMode::Moderate), None)),
            DnsMode::Proton,
            PortForwardingEntitlement::Known(true),
        )
        .expect_err("moderate NAT beside configured port forwarding refuses");
        assert_eq!(error, FeaturesError::NatPortForwardingConflict);
        // Strict NAT against the same config is fine.
        assert_eq!(
            resolve(
                pf_posture,
                Some(&modifier(None, Some(NatMode::Strict), None)),
                DnsMode::Proton,
                PortForwardingEntitlement::Known(true),
            )
            .unwrap()
            .random_nat,
            Some(false)
        );
    }

    /// FR-49A: NetShield needs Proton's DNS. Beside `dns.mode: custom`
    /// every level refuses (config AND modifier); `netshield off` is
    /// the user's way to resolve it, and it does.
    #[test]
    fn fr49a_netshield_beside_custom_dns_refuses_and_off_resolves_it() {
        let mut config = SystemConfig::default();
        config.dns.mode = DnsMode::Custom;
        // Config level: the shipped NetShield default beside custom DNS.
        let error = posture(&config).expect_err("custom DNS beside NetShield refuses");
        assert_eq!(error, FeaturesError::NetShieldCustomDnsConflict);

        // Config level, user resolves it: NetShield off.
        config.features.netshield = NetShieldLevel::Off;
        let custom_off = posture(&config).unwrap();
        assert_eq!(custom_off.netshield_level, Some(EngineNetshield::None));

        // Modifier level: turning NetShield back on beside custom DNS.
        for level in [
            NetshieldLevel::Malware,
            NetshieldLevel::AdsTrackersMalware,
            NetshieldLevel::AdultAdsTrackersMalware,
        ] {
            let error = resolve(
                custom_off,
                Some(&modifier(Some(level), None, None)),
                DnsMode::Custom,
                PortForwardingEntitlement::Unchecked,
            )
            .expect_err("a NetShield level beside custom DNS refuses");
            assert_eq!(
                error,
                FeaturesError::NetShieldCustomDnsConflict,
                "{level:?}"
            );
        }
        // `--netshield off` beside custom DNS resolves the conflict.
        assert_eq!(
            resolve(
                custom_off,
                Some(&modifier(Some(NetshieldLevel::Off), None, None)),
                DnsMode::Custom,
                PortForwardingEntitlement::Unchecked,
            )
            .unwrap()
            .netshield_level,
            Some(EngineNetshield::None)
        );
        // Every OTHER DNS mode coexists with NetShield (System/None
        // mutate no resolver; Proton IS the filtering DNS).
        for mode in [DnsMode::Proton, DnsMode::System, DnsMode::None] {
            config.dns.mode = mode;
            config.features.netshield = NetShieldLevel::AdsTrackersMalware;
            assert!(posture(&config).is_ok(), "{mode:?}");
            assert!(
                resolve(base(), None, mode, PortForwardingEntitlement::Unchecked).is_ok(),
                "{mode:?}"
            );
        }
    }

    /// FR-7: port forwarding is paid-only. A proven paid plan passes;
    /// a proven free plan and an UNVERIFIABLE one both refuse — and
    /// the two refusals are distinguishable (retry vs reconfigure).
    /// Port forwarding OFF never consults the entitlement at all.
    #[test]
    fn fr7_port_forwarding_requires_a_verified_paid_plan() {
        let mut config = SystemConfig::default();
        config.features.port_forwarding = true;
        let pf_posture = posture(&config).unwrap();

        assert_eq!(
            resolve(
                pf_posture,
                None,
                DnsMode::Proton,
                PortForwardingEntitlement::Known(true)
            )
            .unwrap()
            .port_forwarding,
            Some(true)
        );
        assert_eq!(
            resolve(
                pf_posture,
                None,
                DnsMode::Proton,
                PortForwardingEntitlement::Known(false)
            )
            .expect_err("a free plan refuses"),
            FeaturesError::PortForwardingNotEntitled
        );
        assert_eq!(
            resolve(
                pf_posture,
                None,
                DnsMode::Proton,
                PortForwardingEntitlement::Unknown
            )
            .expect_err("no snapshot refuses — fail closed"),
            FeaturesError::PortForwardingEntitlementUnknown
        );
        // With port forwarding OFF the entitlement is never consulted:
        // an unknown or free account connects fine.
        for entitlement in [
            PortForwardingEntitlement::Unknown,
            PortForwardingEntitlement::Known(false),
        ] {
            assert!(
                resolve(base(), None, DnsMode::Proton, entitlement).is_ok(),
                "{entitlement:?}"
            );
        }
    }

    /// The wire codes: an impossible combination is the caller's
    /// parameters (InvalidParams); a missing plan is the account's
    /// (EntitlementMissing — the selection gates' vocabulary).
    #[test]
    fn errors_map_onto_the_wire_vocabulary() {
        use protonwire_frontend_api::RpcErrorCode;
        assert_eq!(
            FeaturesError::NatPortForwardingConflict.to_rpc().code,
            RpcErrorCode::InvalidParams
        );
        assert_eq!(
            FeaturesError::NetShieldCustomDnsConflict.to_rpc().code,
            RpcErrorCode::InvalidParams
        );
        assert_eq!(
            FeaturesError::PortForwardingNotEntitled.to_rpc().code,
            RpcErrorCode::EntitlementMissing
        );
        assert_eq!(
            FeaturesError::PortForwardingEntitlementUnknown
                .to_rpc()
                .code,
            RpcErrorCode::EntitlementMissing
        );
    }
}
