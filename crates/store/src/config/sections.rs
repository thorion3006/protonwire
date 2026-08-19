//! Section and enum types composing the system configuration document
//! (PRD section 10): every type below is a node of the root document
//! (`SystemConfig`, in the parent module), which owns loading and
//! cross-field validation. Each section is `deny_unknown_fields`, so an
//! unknown or misspelled key inside it is a hard parse error.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Daemon section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DaemonSection {
    /// IPC socket path override (system authority).
    pub socket_path: Option<String>,
    /// Group the IPC socket is chowned to so unprivileged clients can
    /// reach it (system authority). Defaults to `Some("protonwire")` — the
    /// group the shipped package provisions (R9-1): with the old `None`
    /// default a standard root launch left the socket root:root 0660 and
    /// every unprivileged client ate EACCES while PRD 433 requires clients
    /// to run unprivileged. An explicit `null` opts out (no chown); the
    /// daemon's bind path applies the chown only when running as root, so
    /// non-root dev launches are unaffected (see `IpcServer::bind_with_group`).
    pub socket_group: Option<String>,
    /// TUN interface name.
    pub interface_name: String,
    /// Log verbosity.
    pub log_level: String,
    /// Uplink integration mode.
    pub network_integration: NetworkIntegrationMode,
}

impl Default for DaemonSection {
    fn default() -> Self {
        Self {
            socket_path: None,
            socket_group: Some("protonwire".into()),
            interface_name: "protonwire0".into(),
            log_level: "info".into(),
            network_integration: NetworkIntegrationMode::Auto,
        }
    }
}

/// Integration modes (PRD 6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkIntegrationMode {
    /// NetworkManager or networkd when either owns the uplink, else native.
    #[default]
    Auto,
    /// Direct netlink observation.
    Native,
    /// Cooperate with NetworkManager.
    NetworkManager,
    /// Cooperate with systemd-networkd.
    Networkd,
}

impl From<NetworkIntegrationMode> for protonwire_frontend_api::NetworkIntegration {
    fn from(mode: NetworkIntegrationMode) -> Self {
        use protonwire_frontend_api::NetworkIntegration as N;
        match mode {
            NetworkIntegrationMode::Auto => N::Auto,
            NetworkIntegrationMode::Native => N::Native,
            NetworkIntegrationMode::NetworkManager => N::NetworkManager,
            NetworkIntegrationMode::Networkd => N::Networkd,
        }
    }
}

/// Account credential section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AccountSection {
    /// Writable session store: `auto`, `keyring`, `tpm2`,
    /// `encrypted-local`, or `none`.
    pub writable_session_store: String,
    /// Priority order of writable stores.
    pub writable_store_priority: Vec<String>,
    /// Credential input source: `interactive` or `systemd`.
    pub credential_input_source: String,
    /// Whether to import a provisioned session at boot.
    pub import_provisioned_session: bool,
    /// Whether a password may be stored at all.
    pub allow_password_storage: bool,
    /// Prefer token over password storage.
    pub prefer_token_storage: bool,
    /// Explicitly-enabled encrypted local fallback.
    pub encrypted_local_fallback: bool,
    /// systemd credential names.
    pub systemd_credential_names: BTreeMap<String, String>,
}

impl Default for AccountSection {
    fn default() -> Self {
        let mut systemd_credential_names = BTreeMap::new();
        systemd_credential_names.insert("session".to_owned(), "protonwire-session".to_owned());
        systemd_credential_names.insert("username".to_owned(), "protonwire-username".to_owned());
        systemd_credential_names.insert("password".to_owned(), "protonwire-password".to_owned());
        Self {
            writable_session_store: "auto".into(),
            writable_store_priority: vec![
                "keyring".into(),
                "tpm2".into(),
                "encrypted-local".into(),
            ],
            credential_input_source: "interactive".into(),
            import_provisioned_session: false,
            allow_password_storage: false,
            prefer_token_storage: true,
            encrypted_local_fallback: false,
            systemd_credential_names,
        }
    }
}

/// Server-selection section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerSelectionSection {
    /// Metadata cache policy.
    pub metadata_cache: MetadataCacheSection,
    /// Latency probing policy.
    pub latency_probe: LatencyProbeSection,
    /// `balanced` policy weights.
    pub balanced_weights: BalancedWeights,
    /// Secure Core defaults.
    pub secure_core: SecureCoreSection,
}

/// Metadata cache policy. The refresh interval floor is a hard product rule:
/// three hours (PRD FR-10..FR-13).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MetadataCacheSection {
    /// Minimum automatic refresh interval in hours.
    pub refresh_interval_hours: u32,
    /// Maximum positive jitter in minutes.
    pub max_positive_jitter_minutes: u32,
    /// ETag/If-None-Match usage.
    pub conditional_requests: bool,
    /// Age beyond which the cache is treated as an emergency.
    pub emergency_max_age_hours: u32,
}

impl Default for MetadataCacheSection {
    fn default() -> Self {
        Self {
            refresh_interval_hours: 3,
            max_positive_jitter_minutes: 10,
            conditional_requests: true,
            emergency_max_age_hours: 24,
        }
    }
}

/// Latency probing policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LatencyProbeSection {
    /// Whether on-demand probing may run at all.
    pub enabled: bool,
    /// Shortlist size.
    pub max_candidates: u32,
    /// Per-probe timeout.
    pub timeout_ms: u32,
    /// Concurrency bound.
    pub parallelism: u32,
    /// Minimum age before a cached result is reused.
    pub result_min_age_minutes: u32,
    /// Background scanning is forbidden by contract.
    pub background_scan: bool,
    /// `tcp-udp` (default) or `icmp` (opt-in, CAP_NET_RAW).
    pub transport: String,
}

impl Default for LatencyProbeSection {
    fn default() -> Self {
        Self {
            enabled: true,
            max_candidates: 20,
            timeout_ms: 750,
            parallelism: 4,
            result_min_age_minutes: 15,
            background_scan: false,
            transport: "tcp-udp".into(),
        }
    }
}

/// Weights of the ProtonWire `balanced` policy (PRD 7.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BalancedWeights {
    /// Weight of Proton-exposed load.
    pub load: f32,
    /// Weight of measured latency.
    pub latency: f32,
    /// Weight of stability history.
    pub stability: f32,
    /// Weight of feature match.
    pub feature_match: f32,
}

impl Default for BalancedWeights {
    fn default() -> Self {
        Self {
            load: 0.40,
            latency: 0.40,
            stability: 0.15,
            feature_match: 0.05,
        }
    }
}

/// Secure Core selection defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecureCoreSection {
    /// Secure Core on by default.
    pub enabled_by_default: bool,
    /// Preferred entry countries.
    pub preferred_entry_countries: Vec<String>,
    /// Excluded entry countries.
    pub excluded_entry_countries: Vec<String>,
    /// Excluded exit countries.
    pub excluded_exit_countries: Vec<String>,
}

/// Connection-group section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ConnectionGroupsSection {
    /// Explicit physical-country override (ISO 3166-1 alpha-2), else the
    /// cached Muon user location is used.
    pub physical_country: Option<String>,
    /// Region taxonomy id; must match the catalog.
    pub region_taxonomy: String,
    /// Default ranking of regional groups.
    pub regional_default_ranking: String,
}

impl Default for ConnectionGroupsSection {
    fn default() -> Self {
        Self {
            physical_country: None,
            region_taxonomy: "un-m49-six-continent-view".into(),
            regional_default_ranking: "proton-score".into(),
        }
    }
}

/// Connection defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ConnectionSection {
    /// Default connect target.
    pub default: String,
    /// Default protocol.
    pub protocol: String,
    /// ProTUN tuning.
    pub protun: ProtunSection,
    /// IPv6 handling.
    pub ipv6: Ipv6Section,
}

impl Default for ConnectionSection {
    fn default() -> Self {
        Self {
            default: "fastest".into(),
            protocol: "smart".into(),
            protun: ProtunSection::default(),
            ipv6: Ipv6Section::default(),
        }
    }
}

/// ProTUN tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProtunSection {
    /// MTU: `auto` or a number.
    pub mtu: String,
    /// SNI strategy for TLS-based transports.
    pub sni_strategy: String,
}

impl Default for ProtunSection {
    fn default() -> Self {
        Self {
            mtu: "auto".into(),
            sni_strategy: "random".into(),
        }
    }
}

/// IPv6 handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ipv6Section {
    /// `auto`, `enabled`, or `disabled`.
    pub mode: String,
}

impl Default for Ipv6Section {
    fn default() -> Self {
        Self {
            mode: "auto".into(),
        }
    }
}

/// Feature defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FeaturesSection {
    /// Secure Core requested.
    pub secure_core: bool,
    /// Kill switch mode.
    pub kill_switch: KillSwitchMode,
    /// Split tunnel mode.
    pub split_tunnel: SplitTunnelMode,
    /// NetShield level.
    pub netshield: NetShieldLevel,
    /// Port forwarding requested.
    pub port_forwarding: bool,
    /// NAT mode.
    pub nat: NatMode,
    /// VPN Accelerator requested.
    pub vpn_accelerator: bool,
}

impl Default for FeaturesSection {
    fn default() -> Self {
        Self {
            secure_core: false,
            kill_switch: KillSwitchMode::On,
            split_tunnel: SplitTunnelMode::Off,
            netshield: NetShieldLevel::AdsTrackersMalware,
            port_forwarding: false,
            nat: NatMode::Strict,
            vpn_accelerator: true,
        }
    }
}

/// Kill switch modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum KillSwitchMode {
    /// No kill switch.
    Off,
    /// Kill switch while the daemon runs.
    #[default]
    On,
    /// Survives daemon stop/crash until explicit disable.
    Permanent,
}

/// Split tunnel modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SplitTunnelMode {
    /// Disabled.
    #[default]
    Off,
    /// Listed traffic bypasses the tunnel.
    Exclude,
    /// Only listed traffic uses the tunnel.
    Include,
}

/// NetShield levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetShieldLevel {
    /// No filtering.
    Off,
    /// Malware only.
    Malware,
    /// Ads, trackers, malware.
    #[default]
    AdsTrackersMalware,
    /// Adult content plus ads, trackers, malware.
    AdultAdsTrackersMalware,
}

/// NAT modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NatMode {
    /// Strict (symmetric) NAT.
    #[default]
    Strict,
    /// Moderate NAT; incompatible with port forwarding.
    Moderate,
}

/// DNS section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DnsSection {
    /// DNS mode.
    pub mode: DnsMode,
    /// Custom resolvers for `custom` mode.
    pub custom_servers: Vec<String>,
    /// Whether DNS is routed through the tunnel.
    pub policy: String,
    /// Leak protection strictness.
    pub leak_protection: String,
    /// Resolvers owned by other software that ProtonWire must not touch.
    pub externally_managed_resolvers: Vec<String>,
}

impl Default for DnsSection {
    fn default() -> Self {
        Self {
            mode: DnsMode::Proton,
            custom_servers: Vec::new(),
            policy: "through-vpn".into(),
            leak_protection: "strict".into(),
            externally_managed_resolvers: Vec::new(),
        }
    }
}

/// DNS modes (PRD 7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DnsMode {
    /// Proton's DNS through the tunnel.
    #[default]
    Proton,
    /// User-supplied resolvers through the tunnel.
    Custom,
    /// Host resolver untouched (requires leak acknowledgment).
    System,
    /// No DNS configuration at all.
    None,
}

/// LAN policy section. `policy` is the sole global LAN setting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LanSection {
    /// Whether LAN traffic may bypass the tunnel.
    pub policy: LanPolicy,
    /// CIDRs considered LAN.
    pub allowed_cidrs: Vec<String>,
}

impl Default for LanSection {
    fn default() -> Self {
        Self {
            policy: LanPolicy::Allow,
            allowed_cidrs: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
                "fd00::/8".into(),
                "fe80::/10".into(),
            ],
        }
    }
}

/// LAN policy values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum LanPolicy {
    /// LAN traffic bypasses the tunnel.
    #[default]
    Allow,
    /// LAN traffic is blocked (group presets like Max security use this).
    Block,
}

/// Split tunnel configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SplitTunnelSection {
    /// Split tunnel mode.
    pub mode: SplitTunnelMode,
    /// Whether running processes may be attached best-effort.
    pub attach_existing_processes: bool,
    /// Domain rule policy.
    pub domains: SplitTunnelDomains,
}

impl Default for SplitTunnelSection {
    fn default() -> Self {
        Self {
            mode: SplitTunnelMode::Off,
            attach_existing_processes: false,
            domains: SplitTunnelDomains::default(),
        }
    }
}

/// Domain split tunneling policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SplitTunnelDomains {
    /// Domain rules enabled.
    pub enabled: bool,
    /// Resolve via DNS observation.
    pub resolver_observation: bool,
    /// Refresh IP sets on TTL expiry.
    pub refresh_on_ttl: bool,
    /// Domain rules.
    pub rules: Vec<SplitTunnelDomainRule>,
}

impl Default for SplitTunnelDomains {
    fn default() -> Self {
        Self {
            enabled: true,
            resolver_observation: true,
            refresh_on_ttl: true,
            rules: Vec::new(),
        }
    }
}

/// One domain split tunnel rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SplitTunnelDomainRule {
    /// Domain pattern (`*.example.com` supported).
    pub domain: String,
    /// `bypass` or `vpn`.
    pub action: String,
    /// TTL handling policy.
    pub ttl_policy: String,
}

impl Default for SplitTunnelDomainRule {
    fn default() -> Self {
        Self {
            domain: String::new(),
            action: "bypass".into(),
            ttl_policy: "respect_dns_ttl".into(),
        }
    }
}

/// Auto-connect policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AutoConnectSection {
    /// Auto-connect at boot.
    pub enabled: bool,
    /// Target for auto-connect.
    pub target: String,
    /// Retry policy.
    pub retry: AutoConnectRetry,
}

impl Default for AutoConnectSection {
    fn default() -> Self {
        Self {
            enabled: false,
            target: "fastest".into(),
            retry: AutoConnectRetry::default(),
        }
    }
}

/// Auto-connect retry policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AutoConnectRetry {
    /// Maximum attempts (0 = unlimited).
    pub max_attempts: u32,
    /// First backoff delay.
    pub initial_delay_seconds: u32,
    /// Backoff ceiling.
    pub max_delay_seconds: u32,
    /// Whether jitter is applied.
    pub jitter: bool,
}

impl Default for AutoConnectRetry {
    fn default() -> Self {
        Self {
            max_attempts: 0,
            initial_delay_seconds: 2,
            max_delay_seconds: 300,
            jitter: true,
        }
    }
}

/// Default profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProfileDefault {
    /// `standard`, `secure-core`, `p2p`, `tor`, or `gateway`.
    pub connection_type: String,
    /// Protocol.
    pub protocol: String,
    /// Selection defaults.
    pub selection: ProfileSelection,
}

impl Default for ProfileDefault {
    fn default() -> Self {
        Self {
            connection_type: "standard".into(),
            protocol: "smart".into(),
            selection: ProfileSelection::default(),
        }
    }
}

/// Default profile selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProfileSelection {
    /// Selection mode.
    pub mode: String,
    /// Ranking policy.
    pub by: String,
    /// Excluded countries.
    pub exclude_countries: Vec<String>,
    /// Required features.
    pub require: Vec<String>,
}

impl Default for ProfileSelection {
    fn default() -> Self {
        Self {
            mode: "fastest".into(),
            by: "official".into(),
            exclude_countries: Vec::new(),
            require: Vec::new(),
        }
    }
}

/// Profiles section (system-side defaults; per-UID profiles arrive with
/// Milestone 6 profile storage).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProfilesSection {
    /// The default profile template.
    pub default: ProfileDefault,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SystemConfig;

    /// pr-champion WO-7 (PRD 6.3): `daemon.socket_group` names the group
    /// the daemon chowns its socket to so unprivileged clients can reach
    /// it. It sits beside `socket_path` and is system authority like its
    /// neighbor. R9-1: the DEFAULT is `Some("protonwire")` — with `None`
    /// a standard root launch left the socket root:root 0660 and every
    /// unprivileged client ate EACCES (PRD 433 requires unprivileged
    /// clients). An explicit `null` remains the documented opt-out.
    #[test]
    fn daemon_socket_group_parses_and_defaults_to_protonwire() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            "schema_version: 2\ndaemon:\n  socket_group: protonwire-clients\n",
        )
        .unwrap();
        let config = SystemConfig::load(&path).unwrap().config;
        config.validate().unwrap();
        assert_eq!(
            config.daemon.socket_group.as_deref(),
            Some("protonwire-clients")
        );
        assert_eq!(
            DaemonSection::default().socket_group.as_deref(),
            Some("protonwire"),
            "the built-in default must name the packaged protonwire group"
        );
        assert_eq!(
            SystemConfig::default().daemon.socket_group.as_deref(),
            Some("protonwire"),
            "the whole-document default must carry the section default"
        );
    }

    /// R9-1: the missing-file soft path hands the built-in defaults to the
    /// daemon, so the defaulted document must carry the group through a
    /// serialize/parse round trip exactly like one read from disk.
    #[test]
    fn config_defaults_round_trip_the_socket_group() {
        let rendered = serde_norway::to_string(&SystemConfig::default()).unwrap();
        let reloaded: SystemConfig = crate::yaml::from_str(&rendered).unwrap();
        reloaded.validate().unwrap();
        assert_eq!(
            reloaded.daemon.socket_group.as_deref(),
            Some("protonwire"),
            "the default group must survive a YAML round trip"
        );
    }

    /// R9-1: an explicit `socket_group: null` is the documented opt-out —
    /// a deployment that manages socket permissions itself (or admits only
    /// root clients) must be able to say "no chown" and get exactly `None`.
    #[test]
    fn explicit_null_socket_group_opts_out_of_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "schema_version: 2\ndaemon:\n  socket_group: null\n").unwrap();
        let config = SystemConfig::load(&path).unwrap().config;
        config.validate().unwrap();
        assert_eq!(
            config.daemon.socket_group, None,
            "an explicit null must override the Some(protonwire) default"
        );
    }

    #[test]
    fn network_integration_mode_maps_to_frontend_enum() {
        use protonwire_frontend_api::NetworkIntegration as N;
        let cases: [(NetworkIntegrationMode, N); 4] = [
            (NetworkIntegrationMode::Auto, N::Auto),
            (NetworkIntegrationMode::Native, N::Native),
            (NetworkIntegrationMode::NetworkManager, N::NetworkManager),
            (NetworkIntegrationMode::Networkd, N::Networkd),
        ];
        for (mode, expected) in cases {
            let mapped: N = mode.into();
            assert_eq!(mapped, expected);
        }
    }
}
