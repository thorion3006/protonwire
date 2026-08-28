//! Section and enum types composing the system configuration document
//! (PRD section 10): every type below is a node of the root document
//! (`SystemConfig`, in the parent module), which owns loading and
//! cross-field validation. Each section is `deny_unknown_fields`, so an
//! unknown or misspelled key inside it is a hard parse error.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Declares a closed-vocabulary enum (M2 S3): the YAML spellings are the
/// exact accepted tokens, and an out-of-vocabulary value is a PARSE error
/// naming the config field path(s) and every accepted spelling — the
/// contract the vocabulary tests pin. Serialization writes the same
/// spelling, so render/reload round trips are stable.
macro_rules! vocabulary {
    (
        $(#[$meta:meta])*
        $name:ident at $field:expr, default $default:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $spelling:expr ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
        }

        impl $name {
            /// The YAML spelling of this value.
            pub const fn as_str(&self) -> &'static str {
                match self { $( Self::$variant => $spelling, )+ }
            }
            /// Every accepted spelling, in document order.
            pub const VOCABULARY: &'static [&'static str] = &[ $( $spelling ),+ ];
            /// The config field path(s) this vocabulary is accepted at.
            pub const FIELD: &'static str = $field;
            /// The accepted spellings rendered for error messages.
            fn expected() -> String {
                Self::VOCABULARY
                    .iter()
                    .map(|spelling| format!("`{spelling}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::$default
            }
        }

        impl TryFrom<String> for $name {
            type Error = String;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                match value.as_str() {
                    $( $spelling => Ok(Self::$variant), )+
                    other => Err(format!(
                        "{} must be one of {} (found `{other}`)",
                        Self::FIELD,
                        Self::expected()
                    )),
                }
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.as_str().to_owned()
            }
        }
    };
}

vocabulary! {
    /// Writable session stores (PRD section 10 account vocabulary:
    /// `auto|keyring|tpm2|encrypted-local|none`; section 9.6's migrate
    /// targets are the three concrete stores).
    WritableSessionStore at "account.writable_session_store / account.writable_store_priority[]", default Auto {
        /// Resolve a store from the priority list.
        Auto => "auto",
        /// freedesktop Secret Service keyring.
        Keyring => "keyring",
        /// TPM2-backed store.
        Tpm2 => "tpm2",
        /// File-backed encrypted store.
        EncryptedLocal => "encrypted-local",
        /// No writable store at all.
        None => "none",
    }
}

vocabulary! {
    /// Where credentials enter the daemon (PRD section 10:
    /// `interactive|systemd`).
    CredentialInputSource at "account.credential_input_source", default Interactive {
        /// Interactive prompt via the credential agent.
        Interactive => "interactive",
        /// systemd credential subsystem, read once at boot.
        Systemd => "systemd",
    }
}

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
    /// Writable session store (see [`WritableSessionStore`]).
    pub writable_session_store: WritableSessionStore,
    /// Priority order of writable stores; entries must name concrete
    /// stores (validated in the root document's `validate`).
    pub writable_store_priority: Vec<WritableSessionStore>,
    /// Credential input source (see [`CredentialInputSource`]).
    pub credential_input_source: CredentialInputSource,
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
            writable_session_store: WritableSessionStore::Auto,
            writable_store_priority: vec![
                WritableSessionStore::Keyring,
                WritableSessionStore::Tpm2,
                WritableSessionStore::EncryptedLocal,
            ],
            credential_input_source: CredentialInputSource::Interactive,
            import_provisioned_session: false,
            allow_password_storage: false,
            prefer_token_storage: true,
            encrypted_local_fallback: false,
            systemd_credential_names,
        }
    }
}

/// Server-selection section.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// The RPC-deadline budget for the per-request entitlement
    /// composition (Codex PR#9, P1): the adapter's own fetch timeout
    /// is 30 s but the IPC request deadline is 10 s — a slow
    /// entitlement endpoint degrades the request to tier-None within
    /// this budget instead of poisoning the client connection.
    /// Validated below the 10 s IPC bar.
    #[serde(default = "default_entitlement_fetch_budget_ms")]
    pub entitlement_fetch_budget_ms: u64,
}

fn default_entitlement_fetch_budget_ms() -> u64 {
    6_000
}

impl Default for ServerSelectionSection {
    fn default() -> Self {
        Self {
            metadata_cache: MetadataCacheSection::default(),
            latency_probe: LatencyProbeSection::default(),
            balanced_weights: BalancedWeights::default(),
            secure_core: SecureCoreSection::default(),
            entitlement_fetch_budget_ms: default_entitlement_fetch_budget_ms(),
        }
    }
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

vocabulary! {
    /// Latency-probe transport (PRD section 10: `tcp-udp` default, `icmp`
    /// opt-in and requires CAP_NET_RAW).
    ProbeTransport at "server_selection.latency_probe.transport", default TcpUdp {
        /// TCP and UDP probes.
        TcpUdp => "tcp-udp",
        /// ICMP probes; opt-in, requires CAP_NET_RAW.
        Icmp => "icmp",
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
    /// TOTAL wall-clock bound on one probe round — the whole round
    /// (every endpoint combined) must finish inside this, stopping
    /// fresh probes at the deadline and keeping the answered prefix.
    /// Sits deliberately under the 10 s IPC request deadline so a
    /// `--by latency` request answers within the RPC timeout (the
    /// Codex PR-9 arithmetic: 20 candidates × 750 ms ≈ 15 s
    /// serialized would otherwise exceed it).
    pub round_deadline_ms: u32,
    /// Concurrency bound.
    pub parallelism: u32,
    /// Minimum age before a cached result is reused.
    pub result_min_age_minutes: u32,
    /// Background scanning is forbidden by contract.
    pub background_scan: bool,
    /// Probe transport (see [`ProbeTransport`]).
    pub transport: ProbeTransport,
}

impl Default for LatencyProbeSection {
    fn default() -> Self {
        Self {
            enabled: true,
            max_candidates: 20,
            timeout_ms: 750,
            round_deadline_ms: 8000,
            parallelism: 4,
            result_min_age_minutes: 15,
            background_scan: false,
            transport: ProbeTransport::TcpUdp,
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

vocabulary! {
    /// Ranking policies for regional connection groups (FR-23P:
    /// Proton score by default; `load`, `latency`, or `balanced` are the
    /// declared overrides — see docs/connection-groups.yaml
    /// `regional_group_ranking_overrides`). FR-19 forbids any
    /// throughput/speed ranking.
    RegionalRanking at "connection_groups.regional_default_ranking", default ProtonScore {
        /// Proton's opaque catalog score (official Fastest semantics).
        ProtonScore => "proton-score",
        /// ProtonWire weighted policy (balanced_weights).
        Balanced => "balanced",
        /// Proton-exposed server load.
        Load => "load",
        /// Locally measured latency.
        Latency => "latency",
    }
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
    /// Default ranking of regional groups (see [`RegionalRanking`]).
    pub regional_default_ranking: RegionalRanking,
}

impl Default for ConnectionGroupsSection {
    fn default() -> Self {
        Self {
            physical_country: None,
            region_taxonomy: "un-m49-six-continent-view".into(),
            regional_default_ranking: RegionalRanking::ProtonScore,
        }
    }
}

vocabulary! {
    /// Connection protocols (FR-32E: `smart`, `wireguard-udp`,
    /// `wireguard-tcp`, `stealth`, all implemented by ProTUN).
    ProtocolMode at "connection.protocol / profiles.default.protocol", default Smart {
        /// ProTUN transport fallback among eligible candidates.
        Smart => "smart",
        /// WireGuard over UDP.
        WireguardUdp => "wireguard-udp",
        /// WireGuard over TCP.
        WireguardTcp => "wireguard-tcp",
        /// TLS-based Stealth transport.
        Stealth => "stealth",
    }
}

vocabulary! {
    /// IPv6 handling (PRD section 10 example `mode: auto`; FR-37 blocks
    /// IPv6 leaks when tunneling is unavailable, NFR-15: tunneled or
    /// blocked).
    Ipv6Mode at "connection.ipv6.mode", default Auto {
        /// Tunnel IPv6 when the server supports it, else block.
        Auto => "auto",
        /// Require IPv6 tunneling.
        Enabled => "enabled",
        /// Block IPv6 entirely.
        Disabled => "disabled",
    }
}

/// Connection defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ConnectionSection {
    /// Default connect target: `fastest`, `random`, `last`,
    /// `group:<namespaced-id>`, or `profile:<name>` (PRD section 10's
    /// literal enumeration; prefix-validated in the root document's
    /// `validate` — S9's CLI selector grammar will be the stricter
    /// validator).
    pub default: String,
    /// Default protocol (see [`ProtocolMode`]).
    pub protocol: ProtocolMode,
    /// ProTUN tuning.
    pub protun: ProtunSection,
    /// IPv6 handling.
    pub ipv6: Ipv6Section,
}

impl Default for ConnectionSection {
    fn default() -> Self {
        Self {
            default: "fastest".into(),
            protocol: ProtocolMode::Smart,
            protun: ProtunSection::default(),
            ipv6: Ipv6Section::default(),
        }
    }
}

/// ProTUN tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProtunSection {
    /// MTU: `auto`, or a quoted integer between 128 and 9000 (validated
    /// in the root document's `validate`; the bound is a sanity range,
    /// not a product rule).
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
    /// IPv6 mode (see [`Ipv6Mode`]).
    pub mode: Ipv6Mode,
}

impl Default for Ipv6Section {
    fn default() -> Self {
        Self {
            mode: Ipv6Mode::Auto,
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

vocabulary! {
    /// DNS routing policy for custom resolvers (FR-49: `through-vpn`,
    /// `bypass-vpn`, or `system-default`, default `through-vpn`; the two
    /// leak exceptions require `dns.leak_protection: off`).
    DnsPolicy at "dns.policy", default ThroughVpn {
        /// Route DNS through the tunnel.
        ThroughVpn => "through-vpn",
        /// Route DNS outside the tunnel (leak exception).
        BypassVpn => "bypass-vpn",
        /// Leave routing to the host (leak exception off-tunnel).
        SystemDefault => "system-default",
    }
}

vocabulary! {
    /// DNS leak-protection strictness (FR-49 names `off` as the
    /// leak-exception companion; section 10 example default `strict`).
    DnsLeakProtection at "dns.leak_protection", default Strict {
        /// Strict leak protection.
        Strict => "strict",
        /// Deliberately off; only valid paired with a leak-exception
        /// policy (FR-49).
        Off => "off",
    }
}

/// DNS section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DnsSection {
    /// DNS mode.
    pub mode: DnsMode,
    /// Custom resolvers for `custom` mode.
    pub custom_servers: Vec<String>,
    /// Custom-DNS routing policy (see [`DnsPolicy`]).
    pub policy: DnsPolicy,
    /// Leak protection strictness (see [`DnsLeakProtection`]).
    pub leak_protection: DnsLeakProtection,
    /// Resolvers owned by other software that ProtonWire must not touch.
    pub externally_managed_resolvers: Vec<String>,
}

impl Default for DnsSection {
    fn default() -> Self {
        Self {
            mode: DnsMode::Proton,
            custom_servers: Vec::new(),
            policy: DnsPolicy::ThroughVpn,
            leak_protection: DnsLeakProtection::Strict,
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

vocabulary! {
    /// Domain split-tunnel rule action (FR-81 / section 7.9 domain-rule
    /// example: `bypass` or `vpn`).
    SplitRuleAction at "split_tunnel.domains.rules[].action", default Bypass {
        /// Matched traffic bypasses the tunnel.
        Bypass => "bypass",
        /// Matched traffic uses the tunnel.
        Vpn => "vpn",
    }
}

/// One domain split tunnel rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SplitTunnelDomainRule {
    /// Domain pattern (`*.example.com` supported).
    pub domain: String,
    /// Rule action (see [`SplitRuleAction`]).
    pub action: SplitRuleAction,
    /// TTL handling policy: `respect_dns_ttl` is the single
    /// PRD-section-10-attested spelling (validated in the root document's
    /// `validate`).
    pub ttl_policy: String,
}

impl Default for SplitTunnelDomainRule {
    fn default() -> Self {
        Self {
            domain: String::new(),
            action: SplitRuleAction::Bypass,
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

vocabulary! {
    /// Profile connection types (FR-23H: Standard, Secure Core, P2P, Tor,
    /// Gateway are explicit constraints; section 7.13 / section 10
    /// example `connection_type: standard`).
    ConnectionType at "profiles.default.connection_type", default Standard {
        /// Standard servers.
        Standard => "standard",
        /// Secure Core entry/exit chain.
        SecureCore => "secure-core",
        /// P2P-friendly servers.
        P2p => "p2p",
        /// Tor-onion servers.
        Tor => "tor",
        /// Dedicated gateways.
        Gateway => "gateway",
    }
}

vocabulary! {
    /// Profile-selection ranking (section 10 example `by: official`;
    /// FR-23P's declared overrides; FR-19 forbids `speed`).
    ProfileRanking at "profiles.default.selection.by", default Official {
        /// Proton's official catalog score.
        Official => "official",
        /// ProtonWire weighted policy.
        Balanced => "balanced",
        /// Proton-exposed server load.
        Load => "load",
        /// Locally measured latency.
        Latency => "latency",
    }
}

/// Default profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProfileDefault {
    /// Profile connection type (see [`ConnectionType`]).
    pub connection_type: ConnectionType,
    /// Protocol (see [`ProtocolMode`]).
    pub protocol: ProtocolMode,
    /// Selection defaults.
    pub selection: ProfileSelection,
}

impl Default for ProfileDefault {
    fn default() -> Self {
        Self {
            connection_type: ConnectionType::Standard,
            protocol: ProtocolMode::Smart,
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
    /// Ranking policy (see [`ProfileRanking`]).
    pub by: ProfileRanking,
    /// Excluded countries.
    pub exclude_countries: Vec<String>,
    /// Required features.
    pub require: Vec<String>,
}

impl Default for ProfileSelection {
    fn default() -> Self {
        Self {
            mode: "fastest".into(),
            by: ProfileRanking::Official,
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

    // ------------------------------------------------------------------
    // M2 S3 vocabulary tests: every stringly-typed field with a PRD-
    // enumerated closed vocabulary becomes an enum whose rejection names
    // the field and the whole accepted vocabulary. The red evidence for
    // each test is behavioral: against the pre-S3 `String` fields the
    // invalid documents below PARSE successfully, so the rejection
    // assertions fail (run on the parent commit to reproduce).
    // ------------------------------------------------------------------

    /// Parses a whole system document, asserting the field-level
    /// rejection message names the field path and every accepted spelling.
    fn assert_rejected(doc: &str, field: &str, spellings: &[&str]) {
        let err = crate::yaml::from_str::<SystemConfig>(doc)
            .expect_err("invalid vocabulary value must be rejected at parse");
        let msg = err.to_string();
        assert!(msg.contains(field), "must name the field: {msg}");
        for spelling in spellings {
            assert!(msg.contains(spelling), "must name `{spelling}`: {msg}");
        }
    }

    /// Parses a whole system document and returns it for field asserts.
    fn parse_doc(doc: &str) -> SystemConfig {
        crate::yaml::from_str::<SystemConfig>(doc).expect("valid vocabulary value must parse")
    }

    /// PRD section 10 (account comment): `auto|keyring|tpm2|encrypted-local|none`.
    #[test]
    fn writable_session_store_vocabulary_enforced() {
        for value in ["auto", "keyring", "tpm2", "encrypted-local", "none"] {
            let config = parse_doc(&format!(
                "schema_version: 2\naccount:\n  writable_session_store: {value}\n"
            ));
            config.validate().unwrap();
        }
        assert_rejected(
            "schema_version: 2\naccount:\n  writable_session_store: icloud\n",
            "account.writable_session_store",
            &["auto", "keyring", "tpm2", "encrypted-local", "none"],
        );
    }

    /// PRD section 10: the priority list carries the same store names
    /// (`keyring`, `tpm2`, `encrypted-local` in the example).
    #[test]
    fn writable_store_priority_vocabulary_enforced() {
        let config =
            parse_doc("schema_version: 2\naccount:\n  writable_store_priority: [tpm2, keyring]\n");
        config.validate().unwrap();
        assert_rejected(
            "schema_version: 2\naccount:\n  writable_store_priority: [floppy]\n",
            "account.writable_store_priority",
            &["keyring", "tpm2", "encrypted-local"],
        );
    }

    /// `auto` and `none` name resolution policy, not concrete stores; a
    /// priority list containing them is meaningless and must be a
    /// validation error naming the field (the list drives S5a's auto
    /// resolution). PRD section 10 example lists exactly the three
    /// concrete stores; section 9.6 migrate targets are the same three.
    #[test]
    fn writable_store_priority_rejects_non_concrete_entries() {
        let parsed = parse_doc("schema_version: 2\naccount:\n  writable_store_priority: [auto]\n");
        let err = parsed
            .validate()
            .expect_err("auto is not a concrete store and must not validate")
            .to_string();
        assert!(
            err.contains("account.writable_store_priority"),
            "must name the field: {err}"
        );
        assert!(
            err.contains("keyring"),
            "must name the accepted stores: {err}"
        );
        let none = parse_doc("schema_version: 2\naccount:\n  writable_store_priority: [none]\n");
        assert!(none.validate().is_err(), "none must not validate either");
    }

    /// PRD section 10 (account comment): `interactive|systemd`. Supersedes
    /// the validate()-time string check (the old suite's
    /// `bad_credential_source_and_transport_rejected`).
    #[test]
    fn credential_input_source_vocabulary_enforced() {
        for value in ["interactive", "systemd"] {
            parse_doc(&format!(
                "schema_version: 2\naccount:\n  credential_input_source: {value}\n"
            ))
            .validate()
            .unwrap();
        }
        assert_rejected(
            "schema_version: 2\naccount:\n  credential_input_source: telepathy\n",
            "account.credential_input_source",
            &["interactive", "systemd"],
        );
    }

    /// FR-49: `through-vpn`, `bypass-vpn`, or `system-default`, default
    /// `through-vpn`; the two leak exceptions pair with
    /// `leak_protection: off` (see the pairing test below).
    #[test]
    fn dns_policy_vocabulary_enforced() {
        let doc = parse_doc("schema_version: 2\ndns:\n  policy: through-vpn\n");
        doc.validate().unwrap();
        for value in ["bypass-vpn", "system-default"] {
            let paired = parse_doc(&format!(
                "schema_version: 2\ndns:\n  policy: {value}\n  leak_protection: off\n"
            ));
            paired.validate().unwrap();
        }
        assert_rejected(
            "schema_version: 2\ndns:\n  policy: always-through-tunnel\n",
            "dns.policy",
            &["through-vpn", "bypass-vpn", "system-default"],
        );
    }

    /// FR-49 names exactly two leak-protection states: `strict` (section
    /// 10 example default) and `off` (the deliberate leak-exception
    /// companion).
    #[test]
    fn dns_leak_protection_vocabulary_enforced() {
        for value in ["strict", "off"] {
            parse_doc(&format!(
                "schema_version: 2\ndns:\n  leak_protection: {value}\n"
            ))
            .validate()
            .unwrap();
        }
        assert_rejected(
            "schema_version: 2\ndns:\n  leak_protection: medium\n",
            "dns.leak_protection",
            &["strict", "off"],
        );
    }

    /// FR-49: the leak-exception policies require `dns.leak_protection: off`.
    #[test]
    fn dns_leak_exception_policies_require_leak_protection_off() {
        for policy in ["bypass-vpn", "system-default"] {
            let parsed = parse_doc(&format!(
                "schema_version: 2\ndns:\n  policy: {policy}\n  leak_protection: strict\n"
            ));
            let err = parsed
                .validate()
                .expect_err("a leak-exception policy requires leak_protection: off")
                .to_string();
            assert!(
                err.contains("dns.policy") && err.contains("leak_protection"),
                "must name both fields: {err}"
            );
        }
        // The paired exception is valid.
        let paired =
            parse_doc("schema_version: 2\ndns:\n  policy: bypass-vpn\n  leak_protection: off\n");
        paired.validate().unwrap();
    }

    /// FR-32E: `smart`, `wireguard-udp`, `wireguard-tcp`, `stealth`; the
    /// same vocabulary at `profiles.default.protocol` (section 10 example).
    #[test]
    fn protocol_vocabulary_enforced() {
        for value in ["smart", "wireguard-udp", "wireguard-tcp", "stealth"] {
            parse_doc(&format!(
                "schema_version: 2\nconnection:\n  protocol: {value}\n"
            ))
            .validate()
            .unwrap();
            parse_doc(&format!(
                "schema_version: 2\nprofiles:\n  default:\n    protocol: {value}\n"
            ))
            .validate()
            .unwrap();
        }
        assert_rejected(
            "schema_version: 2\nconnection:\n  protocol: wireguard-quic\n",
            "connection.protocol",
            &["smart", "wireguard-udp", "wireguard-tcp", "stealth"],
        );
        assert_rejected(
            "schema_version: 2\nprofiles:\n  default:\n    protocol: openvpn\n",
            "profiles.default.protocol",
            &["smart", "wireguard-udp", "wireguard-tcp", "stealth"],
        );
    }

    /// Section 10 example (`mode: auto`) plus the enabled/disabled arms of
    /// the task vocabulary; FR-37/NFR-15 give the semantics.
    #[test]
    fn ipv6_mode_vocabulary_enforced() {
        for value in ["auto", "enabled", "disabled"] {
            parse_doc(&format!(
                "schema_version: 2\nconnection:\n  ipv6:\n    mode: {value}\n"
            ))
            .validate()
            .unwrap();
        }
        assert_rejected(
            "schema_version: 2\nconnection:\n  ipv6:\n    mode: sometimes\n",
            "connection.ipv6.mode",
            &["auto", "enabled", "disabled"],
        );
    }

    /// FR-81 / section 7.9 domain-rule example: `action: bypass` or
    /// `action: vpn`.
    #[test]
    fn split_rule_action_vocabulary_enforced() {
        for value in ["bypass", "vpn"] {
            parse_doc(&format!(
                "schema_version: 2\nsplit_tunnel:\n  domains:\n    rules:\n      - domain: a.test\n        action: {value}\n"
            ))
            .validate()
            .unwrap();
        }
        assert_rejected(
            "schema_version: 2\nsplit_tunnel:\n  domains:\n    rules:\n      - domain: a.test\n        action: maybe\n",
            "split_tunnel.domains.rules[].action",
            &["bypass", "vpn"],
        );
    }

    /// FR-23P / docs/connection-groups.yaml: regional groups rank by
    /// `proton-score` by default and may declare `load`, `latency`, or
    /// `balanced`.
    #[test]
    fn regional_default_ranking_vocabulary_enforced() {
        for value in ["proton-score", "balanced", "load", "latency"] {
            parse_doc(&format!(
                "schema_version: 2\nconnection_groups:\n  regional_default_ranking: {value}\n"
            ))
            .validate()
            .unwrap();
        }
        assert_rejected(
            "schema_version: 2\nconnection_groups:\n  regional_default_ranking: fastest-known\n",
            "connection_groups.regional_default_ranking",
            &["proton-score", "balanced", "load", "latency"],
        );
        // FR-19: a `speed` ranking must FAIL validation, never pass silently.
        assert_rejected(
            "schema_version: 2\nconnection_groups:\n  regional_default_ranking: speed\n",
            "connection_groups.regional_default_ranking",
            &["proton-score", "balanced", "load", "latency"],
        );
    }

    /// FR-23H / section 7.13: `standard`, `secure-core`, `p2p`, `tor`,
    /// `gateway`.
    #[test]
    fn profile_connection_type_vocabulary_enforced() {
        for value in ["standard", "secure-core", "p2p", "tor", "gateway"] {
            parse_doc(&format!(
                "schema_version: 2\nprofiles:\n  default:\n    connection_type: {value}\n"
            ))
            .validate()
            .unwrap();
        }
        assert_rejected(
            "schema_version: 2\nprofiles:\n  default:\n    connection_type: dedicated\n",
            "profiles.default.connection_type",
            &["standard", "secure-core", "p2p", "tor", "gateway"],
        );
    }

    /// Section 10 example (`by: official`) with FR-23P's declared
    /// overrides; FR-19's `speed` must fail validation.
    #[test]
    fn profile_selection_ranking_vocabulary_enforced() {
        for value in ["official", "balanced", "load", "latency"] {
            parse_doc(&format!(
                "schema_version: 2\nprofiles:\n  default:\n    selection:\n      by: {value}\n"
            ))
            .validate()
            .unwrap();
        }
        assert_rejected(
            "schema_version: 2\nprofiles:\n  default:\n    selection:\n      by: vibes\n",
            "profiles.default.selection.by",
            &["official", "balanced", "load", "latency"],
        );
        assert_rejected(
            "schema_version: 2\nprofiles:\n  default:\n    selection:\n      by: speed\n",
            "profiles.default.selection.by",
            &["official", "balanced", "load", "latency"],
        );
    }

    /// Section 10 example (`transport: tcp-udp`): `tcp-udp` default,
    /// `icmp` opt-in (CAP_NET_RAW). Supersedes the validate()-time string
    /// check.
    #[test]
    fn latency_probe_transport_vocabulary_enforced() {
        for value in ["tcp-udp", "icmp"] {
            parse_doc(&format!(
                "schema_version: 2\nserver_selection:\n  latency_probe:\n    transport: {value}\n"
            ))
            .validate()
            .unwrap();
        }
        assert_rejected(
            "schema_version: 2\nserver_selection:\n  latency_probe:\n    transport: carrier-pigeon\n",
            "server_selection.latency_probe.transport",
            &["tcp-udp", "icmp"],
        );
    }

    // ------------------------------------------------------------------
    // rust-review S3 fix 2: the three PRD-attested selector shapes that
    // stay `String` (single-attested-value or open-suffix vocabularies an
    // enum would over-pin) are validated at `validate()`. Red evidence:
    // behavioral — against the parent commit the typo documents below
    // PARSE and VALIDATE cleanly, so the expect_err assertions fail.
    // ------------------------------------------------------------------

    /// PRD section 10 example: `ttl_policy: respect_dns_ttl` — the single
    /// attested spelling. A typo must be a validation error naming the
    /// field and the accepted spelling.
    #[test]
    fn ttl_policy_typo_rejected_by_validate() {
        let parsed = parse_doc(
            "schema_version: 2\nsplit_tunnel:\n  domains:\n    rules:\n      - ttl_policy: respect_dns_ttls\n",
        );
        let err = parsed
            .validate()
            .expect_err("a ttl_policy typo must not validate")
            .to_string();
        assert!(
            err.contains("split_tunnel.domains.rules[0].ttl_policy"),
            "must name the field: {err}"
        );
        assert!(
            err.contains("respect_dns_ttl"),
            "must name the accepted spelling: {err}"
        );

        let good = parse_doc(
            "schema_version: 2\nsplit_tunnel:\n  domains:\n    rules:\n      - ttl_policy: respect_dns_ttl\n",
        );
        good.validate().unwrap();
    }

    /// PRD section 10 example: `mtu: auto`. The field is a string by
    /// schema, so numeric MTUs are quoted strings (`mtu: "1380"`); the
    /// sanity bound 128..=9000 is disclosed in the message. The typo
    /// `atuo` must be a validation error naming both accepted shapes.
    #[test]
    fn protun_mtu_typo_and_out_of_range_rejected_by_validate() {
        for good in ["auto", "\"128\"", "\"1380\"", "\"9000\""] {
            let parsed = parse_doc(&format!(
                "schema_version: 2\nconnection:\n  protun:\n    mtu: {good}\n"
            ));
            parsed.validate().unwrap();
        }
        for bad in ["atuo", "\"0\"", "\"127\"", "\"9001\"", "\"65536\"", "jumbo"] {
            let parsed = parse_doc(&format!(
                "schema_version: 2\nconnection:\n  protun:\n    mtu: {bad}\n"
            ));
            let err = parsed
                .validate()
                .expect_err("an unusable mtu must not validate")
                .to_string();
            assert!(
                err.contains("connection.protun.mtu"),
                "must name the field: {err}"
            );
            assert!(
                err.contains("auto") && err.contains("128") && err.contains("9000"),
                "must name the accepted shapes and the bound: {err}"
            );
        }
    }

    /// PRD section 10 example comment: `fastest|random|last|group:
    /// <namespaced-id>|profile:<name>`. The prefix check rejects the typo
    /// `quickest` while accepting every enumerated shape's suffixes. The
    /// full selector grammar (country/city/server arms) is the CLI's; S9's
    /// grammar will be the stricter validator when it lands.
    #[test]
    fn connection_default_typo_rejected_by_validate() {
        let parsed = parse_doc("schema_version: 2\nconnection:\n  default: quickest\n");
        let err = parsed
            .validate()
            .expect_err("a default-target typo must not validate")
            .to_string();
        assert!(
            err.contains("connection.default"),
            "must name the field: {err}"
        );
        for shape in ["fastest", "random", "last", "group:", "profile:"] {
            assert!(
                err.contains(shape),
                "must name the accepted shape `{shape}`: {err}"
            );
        }

        for good in [
            "fastest",
            "random",
            "last",
            "group:pw-regional-fastest-eu",
            "profile:work",
        ] {
            let parsed = parse_doc(&format!(
                "schema_version: 2\nconnection:\n  default: {good}\n"
            ));
            parsed.validate().unwrap();
        }
    }

    /// The enum spellings must survive a serialize/parse round trip so the
    /// daemon's render-and-reload paths (and `config get` output) are
    /// stable (M2 S3 contract; see also
    /// `config_defaults_round_trip_the_socket_group`). Red evidence: the
    /// disclosed compile-red against this commit's parent (the assertions
    /// name the enum types this commit introduces); the rejection tests
    /// above carry the behavioral reds.
    #[test]
    fn vocabulary_defaults_round_trip() {
        let rendered = serde_norway::to_string(&SystemConfig::default()).unwrap();
        let reloaded: SystemConfig = crate::yaml::from_str(&rendered).unwrap();
        reloaded.validate().unwrap();
        assert_eq!(
            reloaded.account.writable_session_store,
            WritableSessionStore::Auto
        );
        assert_eq!(
            reloaded.account.credential_input_source,
            CredentialInputSource::Interactive
        );
        assert_eq!(reloaded.dns.policy, DnsPolicy::ThroughVpn);
        assert_eq!(reloaded.dns.leak_protection, DnsLeakProtection::Strict);
        assert_eq!(reloaded.connection.protocol, ProtocolMode::Smart);
        assert_eq!(reloaded.connection.ipv6.mode, Ipv6Mode::Auto);
        assert_eq!(reloaded.profiles.default.protocol, ProtocolMode::Smart);
        assert_eq!(
            reloaded.connection_groups.regional_default_ranking,
            RegionalRanking::ProtonScore
        );
        assert_eq!(
            reloaded.profiles.default.connection_type,
            ConnectionType::Standard
        );
        assert_eq!(
            reloaded.profiles.default.selection.by,
            ProfileRanking::Official
        );
        assert_eq!(
            reloaded.server_selection.latency_probe.transport,
            ProbeTransport::TcpUdp
        );
        assert_eq!(
            SplitTunnelDomainRule::default().action,
            SplitRuleAction::Bypass
        );
    }

    /// Rust-review S3 fix 3: the defaults-only pin above leaves the
    /// NON-default spellings' serialize side untested — a variant whose
    /// `as_str` drifted from its match arm would only surface when a
    /// rendered document carrying it stopped reloading. This property
    /// walks every vocabulary's FULL `VOCABULARY`: each spelling parses
    /// to a variant, the variant serializes (both `Into<String>` and the
    /// serde path) back to exactly that spelling, and the spelling
    /// re-parses to the same variant; the default's spelling must itself
    /// be a vocabulary entry. Inspection-level evidence (a pin, not a
    /// red): the macro keeps the two sides in one match today and the
    /// property holds on the parent commit — it exists to hold.
    #[test]
    fn vocabularies_round_trip_every_spelling() {
        macro_rules! round_trip {
            ($($ty:ty),* $(,)?) => {$(
                for spelling in <$ty>::VOCABULARY {
                    let parsed = <$ty>::try_from((*spelling).to_owned())
                        .unwrap_or_else(|error| panic!("{}: {error}", <$ty>::FIELD));
                    let rendered: String = parsed.into();
                    assert_eq!(rendered, *spelling, "{}: serialize drifted", <$ty>::FIELD);
                    let reloaded: $ty = serde_norway::from_str(&rendered)
                        .unwrap_or_else(|error| panic!("{}: {error}", <$ty>::FIELD));
                    assert_eq!(reloaded, parsed, "{}: round trip drifted", <$ty>::FIELD);
                }
                assert!(
                    <$ty>::VOCABULARY.contains(&<$ty>::default().as_str()),
                    "{}: the default spelling must be in the vocabulary",
                    <$ty>::FIELD
                );
            )*};
        }

        round_trip!(
            WritableSessionStore,
            CredentialInputSource,
            ProbeTransport,
            RegionalRanking,
            ProtocolMode,
            Ipv6Mode,
            DnsPolicy,
            DnsLeakProtection,
            SplitRuleAction,
            ConnectionType,
            ProfileRanking,
        );
    }

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
