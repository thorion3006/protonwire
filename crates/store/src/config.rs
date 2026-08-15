//! Typed configuration schema with authority classes (PRD section 10).
//!
//! The system document is root-owned and host-global. The per-UID overlay is
//! a separate document restricted to presentation preferences and per-user
//! selectors; it uses `deny_unknown_fields`, so any attempt to express a
//! system-only setting in an overlay is a parse error (the daemon revalidates
//! on its side as well — T-37 lands with the overlay IPC in Milestone 2).
//!
//! `lan.policy` is the single global LAN setting; there is deliberately no
//! `features.lan_access` configuration field (PRD section 10 closing rule).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::yaml;

/// Who may set a field (PRD section 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Authority {
    /// Only the root-owned system configuration.
    System,
    /// The per-UID user overlay, within administrator ceilings.
    PerUser,
}

/// Daemon section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DaemonSection {
    /// IPC socket path override (system authority).
    pub socket_path: Option<String>,
    /// Group the IPC socket is chowned to so unprivileged clients can
    /// reach it (system authority; unset means no chown).
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
            socket_group: None,
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

/// The root system configuration document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SystemConfig {
    /// Schema version; 2 per PRD section 10.
    pub schema_version: u32,
    /// Daemon section.
    pub daemon: DaemonSection,
    /// Account section.
    pub account: AccountSection,
    /// Server-selection section.
    pub server_selection: ServerSelectionSection,
    /// Connection-group section.
    pub connection_groups: ConnectionGroupsSection,
    /// Connection defaults.
    pub connection: ConnectionSection,
    /// Feature defaults.
    pub features: FeaturesSection,
    /// DNS section.
    pub dns: DnsSection,
    /// LAN section.
    pub lan: LanSection,
    /// Split tunneling section.
    pub split_tunnel: SplitTunnelSection,
    /// Auto-connect section.
    pub auto_connect: AutoConnectSection,
    /// Profiles section.
    pub profiles: ProfilesSection,
}

impl Default for SystemConfig {
    /// Defaults are a *valid* document: the missing-file path hands them to
    /// the daemon, so `schema_version` must already satisfy `validate()`.
    fn default() -> Self {
        Self {
            schema_version: Self::EXPECTED_SCHEMA_VERSION,
            daemon: DaemonSection::default(),
            account: AccountSection::default(),
            server_selection: ServerSelectionSection::default(),
            connection_groups: ConnectionGroupsSection::default(),
            connection: ConnectionSection::default(),
            features: FeaturesSection::default(),
            dns: DnsSection::default(),
            lan: LanSection::default(),
            split_tunnel: SplitTunnelSection::default(),
            auto_connect: AutoConnectSection::default(),
            profiles: ProfilesSection::default(),
        }
    }
}

impl SystemConfig {
    /// Expected schema version of this generation of the document.
    pub const EXPECTED_SCHEMA_VERSION: u32 = 2;

    /// Loads and validates the system configuration; a missing file yields
    /// defaults (with a log record), an invalid file is a hard error.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigLoadError> {
        if !path.exists() {
            tracing::warn!(path = %path.display(), "system configuration not found; using defaults");
            let defaults = Self::default();
            defaults.validate()?;
            return Ok(defaults);
        }
        let config: Self = yaml::from_path(path)?;
        config.validate()?;
        Ok(config)
    }

    /// Validates cross-field rules and returns every violation.
    pub fn validate(&self) -> Result<(), ConfigLoadError> {
        let mut violations = Vec::new();
        if self.schema_version != Self::EXPECTED_SCHEMA_VERSION {
            violations.push(format!(
                "schema_version must be {} (found {})",
                Self::EXPECTED_SCHEMA_VERSION,
                self.schema_version
            ));
        }
        let cache = &self.server_selection.metadata_cache;
        if cache.refresh_interval_hours < 3 {
            violations.push(format!(
                "server_selection.metadata_cache.refresh_interval_hours must be at least 3 (found {})",
                cache.refresh_interval_hours
            ));
        }
        if cache.max_positive_jitter_minutes > 60 {
            violations.push(format!(
                "server_selection.metadata_cache.max_positive_jitter_minutes must be at most 60 (found {})",
                cache.max_positive_jitter_minutes
            ));
        }
        let weights = &self.server_selection.balanced_weights;
        let weight_values = [
            weights.load,
            weights.latency,
            weights.stability,
            weights.feature_match,
        ];
        let sum: f32 = weight_values.iter().sum();
        // NaN comparisons are false, so an explicit finiteness check is
        // required or `.nan` weights slip through (rust-review finding 6).
        if !weight_values.iter().all(|w| w.is_finite())
            || weight_values.iter().any(|w| *w < 0.0)
            || (sum - 1.0).abs() > 0.001
        {
            violations.push(format!(
                "server_selection.balanced_weights must be finite, non-negative, and sum to 1.0 (found {sum:.4})"
            ));
        }
        if self.server_selection.latency_probe.background_scan {
            violations.push(
                "server_selection.latency_probe.background_scan is forbidden by contract"
                    .to_owned(),
            );
        }
        if self.features.port_forwarding && self.features.nat == NatMode::Moderate {
            violations.push(
                "features.port_forwarding is incompatible with features.nat=moderate".to_owned(),
            );
        }
        if self.dns.mode == DnsMode::Custom && self.dns.custom_servers.is_empty() {
            violations
                .push("dns.mode=custom requires at least one dns.custom_servers entry".to_owned());
        }
        if !matches!(
            self.account.credential_input_source.as_str(),
            "interactive" | "systemd"
        ) {
            violations.push(format!(
                "account.credential_input_source must be interactive or systemd (found {})",
                self.account.credential_input_source
            ));
        }
        if !matches!(
            self.server_selection.latency_probe.transport.as_str(),
            "tcp-udp" | "icmp"
        ) {
            violations.push(format!(
                "server_selection.latency_probe.transport must be tcp-udp or icmp (found {})",
                self.server_selection.latency_probe.transport
            ));
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(ConfigLoadError::Validation { violations })
        }
    }

    /// Field-level authority report used by tests and diagnostics. Paths use
    /// dotted notation against the document root.
    pub fn authority_report(&self) -> Vec<(&'static str, Authority)> {
        vec![
            ("daemon", Authority::System),
            ("account", Authority::System),
            ("server_selection.metadata_cache", Authority::System),
            ("server_selection.latency_probe", Authority::System),
            ("server_selection.balanced_weights", Authority::System),
            ("server_selection.secure_core", Authority::System),
            ("connection_groups", Authority::System),
            ("connection", Authority::System),
            ("dns", Authority::System),
            ("lan", Authority::System),
            ("split_tunnel", Authority::System),
            ("auto_connect", Authority::System),
            ("features", Authority::PerUser),
            ("profiles", Authority::PerUser),
        ]
    }
}

/// Configuration loading failures.
#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    /// The document could not be parsed.
    #[error(transparent)]
    Yaml(#[from] yaml::YamlError),
    /// Cross-field validation failed.
    #[error("configuration validation failed:\n  - {}",
        violations.join("\n  - "))]
    Validation {
        /// Every violation, in document order.
        violations: Vec<String>,
    },
}

/// Client output format preference (per-UID overlay field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum OutputFormat {
    /// Human-readable output.
    #[default]
    Human,
    /// Machine-readable JSON output.
    Json,
}

/// Per-UID user overlay: presentation preferences and per-user selectors
/// only. Any system-only key here is a parse error by construction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UserOverlay {
    /// Schema version (same generation as the system document).
    pub schema_version: u32,
    /// Presentation preferences.
    pub presentation: UserPresentation,
}

/// Presentation preferences.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UserPresentation {
    /// Default CLI output format.
    pub default_output: Option<OutputFormat>,
}

#[cfg(test)]
mod tests {
    // Tests mutate single fields of defaulted documents; struct-update
    // syntax everywhere would hurt readability here.
    #![allow(clippy::field_reassign_with_default)]

    use super::*;

    const PRD_EXAMPLE: &str = include_str!("../../../docs/PRD-proton-wire.md");

    fn example_config_yaml() -> String {
        // Extract the fenced YAML example from PRD section 10 so the typed
        // schema is tested against the document it implements.
        let start = PRD_EXAMPLE
            .find("## 10. Configuration Schema")
            .expect("section 10 header");
        let rest = &PRD_EXAMPLE[start..];
        let first = rest.find("```yaml\n").expect("yaml fence");
        let after = &rest[first + "```yaml\n".len()..];
        let end = after.find("```").expect("closing fence");
        after[..end].to_owned()
    }

    #[test]
    fn parses_prd_example_config() {
        let config: SystemConfig = crate::yaml::from_str(&example_config_yaml()).unwrap();
        config.validate().unwrap();
        assert_eq!(config.schema_version, 2);
        assert_eq!(config.daemon.interface_name, "protonwire0");
        assert_eq!(
            config.daemon.network_integration,
            NetworkIntegrationMode::Auto
        );
        assert_eq!(
            config
                .server_selection
                .metadata_cache
                .refresh_interval_hours,
            3
        );
        assert_eq!(config.features.kill_switch, KillSwitchMode::On);
        assert_eq!(config.features.nat, NatMode::Strict);
        assert_eq!(config.dns.mode, DnsMode::Proton);
        assert_eq!(config.lan.policy, LanPolicy::Allow);
        assert_eq!(config.lan.allowed_cidrs.len(), 5);
    }

    #[test]
    fn defaults_validate() {
        SystemConfig::default().validate().unwrap();
    }

    #[test]
    fn load_missing_file_yields_valid_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = SystemConfig::load(&dir.path().join("absent.yaml")).unwrap();
        assert_eq!(config.schema_version, SystemConfig::EXPECTED_SCHEMA_VERSION);
        config.validate().unwrap();
    }

    #[test]
    fn load_invalid_yaml_is_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "daemon: [broken\n").unwrap();
        assert!(matches!(
            SystemConfig::load(&path),
            Err(ConfigLoadError::Yaml(_))
        ));
    }

    #[test]
    fn load_invalid_document_reports_violations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, "schema_version: 1\n").unwrap();
        let err = SystemConfig::load(&path).unwrap_err();
        assert!(err.to_string().contains("schema_version"), "got: {err}");
    }

    #[test]
    fn load_valid_document_parses_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, example_config_yaml()).unwrap();
        let config = SystemConfig::load(&path).unwrap();
        assert_eq!(config.daemon.interface_name, "protonwire0");
    }

    /// pr-champion WO-7 (PRD 6.3): `daemon.socket_group` names the group
    /// the daemon chowns its socket to so unprivileged clients can reach
    /// it. It sits beside `socket_path`, defaults to unset (no chown), and
    /// is system authority like its neighbor.
    #[test]
    fn daemon_socket_group_parses_and_defaults_to_unset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        std::fs::write(
            &path,
            "schema_version: 2\ndaemon:\n  socket_group: protonwire-clients\n",
        )
        .unwrap();
        let config = SystemConfig::load(&path).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.daemon.socket_group.as_deref(),
            Some("protonwire-clients")
        );
        assert!(SystemConfig::default().daemon.socket_group.is_none());
    }

    #[test]
    fn refresh_interval_floor_enforced() {
        let mut config = SystemConfig::default();
        config
            .server_selection
            .metadata_cache
            .refresh_interval_hours = 2;
        let err = config.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("at least 3"), "got: {msg}");
    }

    #[test]
    fn all_violations_reported_together() {
        let mut config = SystemConfig::default();
        config.schema_version = 1;
        config
            .server_selection
            .metadata_cache
            .refresh_interval_hours = 1;
        config.features.port_forwarding = true;
        config.features.nat = NatMode::Moderate;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("schema_version"), "got: {err}");
        assert!(err.contains("at least 3"));
        assert!(err.contains("moderate"));
    }

    #[test]
    fn dns_custom_requires_servers() {
        let mut config = SystemConfig::default();
        config.dns.mode = DnsMode::Custom;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("custom_servers"), "got: {err}");
    }

    #[test]
    fn bad_credential_source_and_transport_rejected() {
        let mut config = SystemConfig::default();
        config.account.credential_input_source = "telepathy".into();
        config.server_selection.latency_probe.transport = "carrier-pigeon".into();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("credential_input_source"), "got: {err}");
        assert!(err.contains("tcp-udp or icmp"), "got: {err}");
    }

    #[test]
    fn jitter_ceiling_enforced() {
        let mut config = SystemConfig::default();
        config
            .server_selection
            .metadata_cache
            .max_positive_jitter_minutes = 61;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("max_positive_jitter_minutes"), "got: {err}");
    }

    #[test]
    fn port_forwarding_moderate_nat_conflict() {
        let mut config = SystemConfig::default();
        config.schema_version = 2;
        config.features.port_forwarding = true;
        config.features.nat = NatMode::Moderate;
        assert!(config.validate().is_err());
    }

    #[test]
    fn background_scan_forbidden() {
        let mut config = SystemConfig::default();
        config.schema_version = 2;
        config.server_selection.latency_probe.background_scan = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn balanced_weights_must_sum_to_one() {
        let mut config = SystemConfig::default();
        config.server_selection.balanced_weights.latency = 0.9;
        assert!(config.validate().is_err());
    }

    /// Rust-review finding 6: NaN defeats `(sum - 1.0).abs() > 0.001` (all
    /// NaN comparisons are false) and negative weights summing to 1.0 are
    /// nonsense — both must be rejected.
    #[test]
    fn non_finite_and_negative_weights_rejected() {
        let mut config = SystemConfig::default();
        config.server_selection.balanced_weights.latency = f32::NAN;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("finite"), "got: {err}");

        let mut config = SystemConfig::default();
        config.server_selection.balanced_weights.load = -0.1;
        config.server_selection.balanced_weights.latency = 0.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn schema_version_mismatch_rejected() {
        let mut config = SystemConfig::default();
        config.schema_version = 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn user_overlay_rejects_system_only_fields() {
        let overlay = "schema_version: 2\ndaemon:\n  log_level: debug\n";
        let err = crate::yaml::from_str::<UserOverlay>(overlay).unwrap_err();
        assert!(err.to_string().contains("daemon"), "got: {err}");
    }

    #[test]
    fn user_overlay_parses_presentation() {
        let overlay = "schema_version: 2\npresentation:\n  default_output: json\n";
        let parsed: UserOverlay = crate::yaml::from_str(overlay).unwrap();
        assert_eq!(parsed.presentation.default_output, Some(OutputFormat::Json));
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

    #[test]
    fn authority_report_has_single_lan_authority() {
        let config = SystemConfig::default();
        let report = config.authority_report();
        assert!(report.contains(&("lan", Authority::System)));
        // No second LAN field exists anywhere in the authority table; match
        // the exact segment so unrelated words containing "lan" (as in
        // "balanced_weights") do not false-positive.
        let lan_entries = report
            .iter()
            .filter(|(path, _)| *path == "lan" || path.starts_with("lan."))
            .count();
        assert_eq!(lan_entries, 1);
    }
}
