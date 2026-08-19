//! Typed configuration schema with authority classes (PRD section 10).
//!
//! The module family: this module owns the system document —
//! [`SystemConfig`], the load paths (`load`, `load_strict`), cross-field
//! `validate`, the [`Authority`] table, and [`ConfigLoadError`];
//! `sections` owns the section and enum types the document is composed
//! of; `overlay` owns the per-UID [`UserOverlay`] document.
//!
//! The system document is root-owned and host-global. The per-UID overlay is
//! a separate document restricted to presentation preferences and per-user
//! selectors; it uses `deny_unknown_fields`, so any attempt to express a
//! system-only setting in an overlay is a parse error (the daemon revalidates
//! on its side as well — T-37 lands with the overlay IPC in Milestone 2).
//!
//! `lan.policy` is the single global LAN setting; there is deliberately no
//! `features.lan_access` configuration field (PRD section 10 closing rule).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::fs_trust::{FsTrustError, MissingLeaf, verify_trusted_path};
use crate::yaml;

mod overlay;
mod sections;

pub use overlay::{OutputFormat, UserOverlay, UserPresentation};
pub use sections::{
    AccountSection, AutoConnectRetry, AutoConnectSection, BalancedWeights, ConnectionGroupsSection,
    ConnectionSection, DaemonSection, DnsMode, DnsSection, FeaturesSection, Ipv6Section,
    KillSwitchMode, LanPolicy, LanSection, LatencyProbeSection, MetadataCacheSection, NatMode,
    NetShieldLevel, NetworkIntegrationMode, ProfileDefault, ProfileSelection, ProfilesSection,
    ProtunSection, SecureCoreSection, ServerSelectionSection, SplitTunnelDomainRule,
    SplitTunnelDomains, SplitTunnelMode, SplitTunnelSection,
};

/// Who may set a field (PRD section 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Authority {
    /// Only the root-owned system configuration.
    System,
    /// The per-UID user overlay, within administrator ceilings.
    PerUser,
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

/// The outcome of [`SystemConfig::load`]: the validated document plus
/// whether it came from disk or from the built-in defaults.
///
/// `used_defaults` exists because load's own `tracing::warn!` for a
/// missing file can fire before the caller installs a subscriber (the
/// daemon loads config before initializing logging so `daemon.log_level`
/// applies) — a caller that needs the warning surfaced re-emits it from
/// this flag after logging initializes (pr-champion WO-9).
#[derive(Debug, Clone)]
pub struct LoadedSystemConfig {
    /// The validated configuration document.
    pub config: SystemConfig,
    /// True when the path was absent and built-in defaults were used.
    pub used_defaults: bool,
}

impl SystemConfig {
    /// Expected schema version of this generation of the document.
    pub const EXPECTED_SCHEMA_VERSION: u32 = 2;

    /// Loads and validates the system configuration with the loader's
    /// original read-anything semantics. Only *absence* is soft: a
    /// missing file yields defaults (with a log record). A file that
    /// cannot be read (an EACCES ancestor directory, for example) is a
    /// hard error — `exists()` would read that as "missing" and hand the
    /// daemon silent defaults for its socket, credential, and protection
    /// policy — and an invalid file is equally hard.
    ///
    /// The result's [`LoadedSystemConfig::used_defaults`] flag says when
    /// the defaults path was taken, so a caller whose subscriber is not up
    /// yet can re-emit the missing-file warning after initializing
    /// logging.
    ///
    /// This entry point performs NO trust checks: the root daemon loads
    /// through [`SystemConfig::load_strict`] (round-8 X5), and only it —
    /// the per-UID overlay and ordinary test paths keep these semantics
    /// (strictness is parameterized, not blanket-applied).
    pub fn load(path: &Path) -> Result<LoadedSystemConfig, ConfigLoadError> {
        Self::load_inner(path, None)
    }

    /// Loads and validates the system configuration in strict mode
    /// (round-8 X5, sshd `StrictModes`-style): before the document is
    /// read, [`crate::fs_trust`] walks the leaf AND every ancestor
    /// directory up to and including `trust_root`, hard-rejecting any
    /// component that is a symlink, has the wrong type, grants group or
    /// world write, or is not owned by root (uid 0, gid 0). Anyone able
    /// to plant or replace the document would otherwise control
    /// root-daemon policy.
    ///
    /// Walk rule: production callers pass `/` as the trust root — the
    /// sshd rule, and correct here because `/etc` and every parent is
    /// root-owned 0755 on a real system, so the walk to `/` rejects only
    /// genuinely hostile trees. A shallower root is an explicit opt-in
    /// for hermetic tests, which construct the whole tree under the root
    /// and trust everything above it by construction.
    ///
    /// Absence of the leaf stays soft exactly as in [`SystemConfig::load`]
    /// (defaults, `used_defaults`), but the ancestors are still walked: a
    /// symlinked ancestor does not become acceptable because the leaf it
    /// would point at is absent. Like sshd's check this is a
    /// happens-before-use walk, not an atomic guarantee against a
    /// concurrent swap.
    pub fn load_strict(
        path: &Path,
        trust_root: &Path,
    ) -> Result<LoadedSystemConfig, ConfigLoadError> {
        Self::load_inner(path, Some(trust_root))
    }

    /// The shared load body; `trust_root` selects the strict walk.
    fn load_inner(
        path: &Path,
        trust_root: Option<&Path>,
    ) -> Result<LoadedSystemConfig, ConfigLoadError> {
        if let Some(trust_root) = trust_root {
            // A missing LEAF stays soft (the read below yields defaults),
            // but only through a clean tree: every ancestor is still
            // walked, and a present leaf is fully checked before read.
            verify_trusted_path(path, trust_root, MissingLeaf::Allow)?;
        }
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(path = %path.display(), "system configuration not found; using defaults");
                let defaults = Self::default();
                defaults.validate()?;
                return Ok(LoadedSystemConfig {
                    config: defaults,
                    used_defaults: true,
                });
            }
            Err(error) => {
                return Err(ConfigLoadError::Io {
                    path: path.to_path_buf(),
                    source: error,
                });
            }
        };
        let config: Self = yaml::from_slice(&bytes)?;
        config.validate()?;
        Ok(LoadedSystemConfig {
            config,
            used_defaults: false,
        })
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
    /// The document could not be read (absence is NOT this variant — only
    /// a missing file yields defaults).
    #[error("failed to read system configuration from {path}: {source}")]
    Io {
        /// The path that could not be read.
        path: std::path::PathBuf,
        /// The underlying I/O failure.
        source: std::io::Error,
    },
    /// Strict-mode trust walk failed (round-8 X5): the system
    /// configuration file or one of its ancestor directories is a
    /// symlink, has the wrong type, is not owned by root, or grants
    /// group/world write. Anyone able to plant or replace the document
    /// would control root-daemon policy, so the defect is hard: the
    /// message names the offending component and what is wrong with it.
    #[error("untrusted system configuration: {0}")]
    UntrustedPath(#[from] FsTrustError),
    /// Cross-field validation failed.
    #[error("configuration validation failed:\n  - {}",
        violations.join("\n  - "))]
    Validation {
        /// Every violation, in document order.
        violations: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    // Tests mutate single fields of defaulted documents; struct-update
    // syntax everywhere would hurt readability here.
    #![allow(clippy::field_reassign_with_default)]

    use super::*;

    const PRD_EXAMPLE: &str = include_str!("../../../../docs/PRD-proton-wire.md");

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
        // R9-1: the example must carry the client-admission group — the
        // default the shipped package provisions (it creates the
        // `protonwire` group; an absent group on a dev box is the
        // non-root-gated bind path, see server.rs).
        assert_eq!(
            config.daemon.socket_group.as_deref(),
            Some("protonwire"),
            "the PRD section 10 example must pin the default socket group"
        );
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
        let config = SystemConfig::load(&dir.path().join("absent.yaml"))
            .unwrap()
            .config;
        assert_eq!(config.schema_version, SystemConfig::EXPECTED_SCHEMA_VERSION);
        config.validate().unwrap();
    }

    /// pr-champion WO-9: load's `tracing::warn!` for a missing file fires
    /// before the daemon installs its subscriber, so the warning is
    /// discarded. `load` must report whether defaults were substituted so
    /// the daemon can re-emit the warning after logging initializes. Red
    /// evidence pre-fix is the disclosed compile-red (`used_defaults` did
    /// not exist on the load result).
    #[test]
    fn load_reports_whether_defaults_were_used() {
        let dir = tempfile::tempdir().unwrap();
        let missing = SystemConfig::load(&dir.path().join("absent.yaml")).unwrap();
        assert!(
            missing.used_defaults,
            "a missing file must flag used_defaults"
        );
        assert_eq!(
            missing.config.schema_version,
            SystemConfig::EXPECTED_SCHEMA_VERSION
        );

        let path = dir.path().join("config.yaml");
        std::fs::write(&path, example_config_yaml()).unwrap();
        let present = SystemConfig::load(&path).unwrap();
        assert!(
            !present.used_defaults,
            "a document loaded from disk must not flag used_defaults"
        );
    }

    /// Review-fix V4: `load` used `!path.exists()`, so an EACCES ancestor
    /// read as "missing" and the daemon got silent defaults for its socket,
    /// credential, and protection policy. A config under a mode-0000 parent
    /// must be a hard error naming the path and the underlying failure —
    /// never defaults. Mirrors the suite's non-root-only permission pattern.
    #[test]
    fn load_unreadable_config_is_hard_error_not_defaults() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let closed = dir.path().join("closed");
        std::fs::create_dir(&closed).unwrap();
        let path = closed.join("config.yaml");
        std::fs::write(&path, example_config_yaml()).unwrap();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let outcome = SystemConfig::load(&path);
        // Root ignores DAC, so the denial is only provable for non-root
        // test users (the pattern used by the ipc suite).
        let provable = std::fs::read(&path).is_err();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
        if !provable {
            return; // running as root: the mode bits deny nothing
        }
        let err = outcome.expect_err("an unreadable config must be a hard error");
        let message = err.to_string();
        assert!(
            message.contains("config.yaml"),
            "must name the path: {message}"
        );
        assert!(
            message.contains("Permission denied"),
            "must name the underlying error: {message}"
        );
    }

    /// Round-8 X5 [ZkI1F]: the root daemon applies whatever document sits
    /// at the system config path, so that path is a privilege-escalation
    /// surface — an unprivileged user able to plant or replace the file
    /// (by owning it, sharing a writable group, or symlinking it)
    /// controls root-daemon policy. The strict arms below pin the
    /// sshd-`StrictModes`-style trust walk `load_strict` performs before
    /// reading: root-owned, no group/world write, no symlinks, on the
    /// leaf AND every ancestor up to the trust root.
    ///
    /// Fixture: a config tree under a tempdir that stands in for
    /// `/etc/protonwire`, with the tempdir as the trust root — hermetic
    /// tests control the whole tree under the temp root (the walk-to-`/`
    /// rule itself is pinned by the daemon suite, which exercises the
    /// production call).
    fn strict_config_tree(root: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = root.join("etc").join("protonwire");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("config.yaml");
        std::fs::write(&path, "schema_version: 2\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        path
    }

    /// X5 mode arm (leaf), the finding's exact scenario: a group-writable
    /// config file must be a hard rejection naming the file and the mode
    /// defect. Fully provable unprivileged — chmod needs no privileges,
    /// and the walk's mode pass runs before its ownership pass, so a
    /// user-owned file never shadows the mode defect.
    /// rust-review round 8 (live-reproduced against the daemon): an ABSENT
    /// ancestor directory under the trust root used to hard-fail the
    /// strict walk — "untrusted ... could not inspect" (the misnomer; the
    /// daemon exited 15) — when a missing component can carry no defect
    /// and no leaf can exist beneath it. Absence stays soft; ancestors
    /// that do exist are still verified. The unprivileged runner cannot
    /// build an existing root-owned ancestor chain, so the chain here is
    /// absent from a missing trust root down (the daemon-level repro
    /// against `/` — exit 15 pre-fix, defaults post-fix — is recorded in
    /// the fix commit).
    #[test]
    fn strict_load_missing_ancestor_dir_stays_soft() {
        let root = tempfile::tempdir().unwrap();
        let trust_root = root.path().join("not-there-yet");
        let missing = trust_root.join("config.yaml");
        let loaded = SystemConfig::load_strict(&missing, &trust_root).unwrap();
        assert!(
            loaded.used_defaults,
            "an absent ancestor directory must select defaults, not exit 15"
        );
    }

    #[test]
    fn strict_load_rejects_group_writable_file() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = strict_config_tree(root.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        let err = SystemConfig::load_strict(&path, root.path()).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigLoadError::UntrustedPath(
                    crate::fs_trust::FsTrustError::GroupWorldWritable { .. }
                )
            ),
            "must be the mode defect: {err}"
        );
        let message = err.to_string();
        assert!(
            message.contains("config.yaml"),
            "must name the offending path: {message}"
        );
        assert!(
            message.contains("group/world write"),
            "must name the defect: {message}"
        );
    }

    /// X5 ownership arm (leaf): the document must be owned by root uid
    /// AND gid. Unprivileged runners construct the arm for free (their
    /// files are non-root-owned by construction); root runners hand the
    /// file to uid/gid 65534 (nobody). When neither construction is
    /// possible the arm is unprovable and skipped — the suite's
    /// established pattern (see the 0000-dir test above).
    #[test]
    fn strict_load_rejects_non_root_owned_file() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let path = strict_config_tree(root.path());
        if std::fs::metadata(&path).unwrap().uid() == 0 {
            // Running as root: hand the file away.
            let _ = std::os::unix::fs::chown(&path, Some(65534), Some(65534));
        }
        let meta = std::fs::metadata(&path).unwrap();
        if meta.uid() == 0 && meta.gid() == 0 {
            return; // cannot construct a non-root-owned file here
        }
        let err = SystemConfig::load_strict(&path, root.path()).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigLoadError::UntrustedPath(crate::fs_trust::FsTrustError::NotRootOwned { .. })
            ),
            "must be the ownership defect: {err}"
        );
        assert!(
            err.to_string().contains("owned by uid"),
            "must name the ownership defect: {err}"
        );
    }

    /// X5 mode arm (ancestor): a world-writable ancestor directory lets
    /// any local user swap the document into place, so the walk rejects
    /// the directory itself. Provable unprivileged for the same reason as
    /// the leaf arm: mode is checked before ownership.
    #[test]
    fn strict_load_rejects_world_writable_ancestor_dir() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = strict_config_tree(root.path());
        let dir = path.parent().unwrap(); // .../etc/protonwire
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = SystemConfig::load_strict(&path, root.path()).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigLoadError::UntrustedPath(
                    crate::fs_trust::FsTrustError::GroupWorldWritable { .. }
                )
            ),
            "must be the ancestor's mode defect: {err}"
        );
        let message = err.to_string();
        assert!(
            message.contains("protonwire"),
            "must name the offending directory: {message}"
        );
        assert!(
            message.contains("group/world write"),
            "must name the defect: {message}"
        );
    }

    /// X5 symlink arm (leaf): a symlinked config.yaml is a hard rejection
    /// even when its target is a perfectly clean file — the link itself
    /// is the defect (every component is lstat'd, never followed).
    #[test]
    fn strict_load_rejects_symlinked_config_file() {
        let root = tempfile::tempdir().unwrap();
        let path = strict_config_tree(root.path());
        let real = path.with_file_name("config.real.yaml");
        std::fs::rename(&path, &real).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        let err = SystemConfig::load_strict(&path, root.path()).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigLoadError::UntrustedPath(crate::fs_trust::FsTrustError::Symlink { .. })
            ),
            "must be the symlink defect: {err}"
        );
        let message = err.to_string();
        assert!(
            message.contains("config.yaml"),
            "must name the link path: {message}"
        );
        assert!(
            message.contains("symbolic link"),
            "must name the defect: {message}"
        );
    }

    /// X5 symlink arm (ancestor) plus the laundering attempt: a symlinked
    /// ancestor is rejected when the leaf through it exists, and a
    /// missing leaf does not launder it — absence stays soft only through
    /// a clean tree.
    #[test]
    fn strict_load_rejects_symlinked_ancestor_even_with_missing_leaf() {
        let root = tempfile::tempdir().unwrap();
        // The real tree the link points at, and the linked path the
        // loader is asked to trust.
        let real_dir = root.path().join("real").join("protonwire");
        std::fs::create_dir_all(&real_dir).unwrap();
        let real_file = real_dir.join("config.yaml");
        std::fs::write(&real_file, "schema_version: 2\n").unwrap();
        let link = root.path().join("etc");
        std::os::unix::fs::symlink(root.path().join("real"), &link).unwrap();
        let via = link.join("protonwire").join("config.yaml");

        let err = SystemConfig::load_strict(&via, root.path()).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigLoadError::UntrustedPath(crate::fs_trust::FsTrustError::Symlink { .. })
            ),
            "must be the symlink defect: {err}"
        );
        assert!(
            err.to_string().contains("etc"),
            "must name the linked ancestor, not the leaf: {err}"
        );

        // Laundering attempt: delete the leaf so absence would read as
        // "use defaults" — the symlinked ancestor must still reject.
        std::fs::remove_file(&real_file).unwrap();
        let err = SystemConfig::load_strict(&via, root.path()).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigLoadError::UntrustedPath(crate::fs_trust::FsTrustError::Symlink { .. })
            ),
            "a missing leaf must not launder a symlinked ancestor: {err}"
        );
    }

    /// X5 positive arm, root-gated per the established skip pattern: only
    /// a runner whose created files read as root:root can construct the
    /// accepted tree (unprivileged runners cannot chown to root). The
    /// tree mimics the real deployment — root:root 0644 file, 0755
    /// directories, up to the trust root — and must load; a missing leaf
    /// through that clean tree must stay soft (defaults).
    #[test]
    fn strict_load_accepts_clean_root_owned_tree() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let path = strict_config_tree(root.path());
        let clean_and_root_owned = [
            root.path().to_path_buf(),
            root.path().join("etc"),
            path.clone(),
        ]
        .iter()
        .all(|component| {
            let meta = std::fs::metadata(component).unwrap();
            meta.uid() == 0 && meta.gid() == 0
        });
        if !clean_and_root_owned {
            return; // uid-0 ownership arm unprovable for this runner
        }
        let loaded = SystemConfig::load_strict(&path, root.path()).unwrap();
        assert!(
            !loaded.used_defaults,
            "a clean root-owned document must load"
        );
        assert_eq!(
            loaded.config.schema_version,
            SystemConfig::EXPECTED_SCHEMA_VERSION
        );

        // Absence stays soft in strict mode — through a clean tree a
        // missing leaf yields defaults, exactly like plain `load`.
        std::fs::remove_file(&path).unwrap();
        let missing = SystemConfig::load_strict(&path, root.path()).unwrap();
        assert!(
            missing.used_defaults,
            "a clean tree with no leaf must yield defaults"
        );
    }

    /// X5 parameterization pin: strictness is the SYSTEM-authority load's
    /// rule, not a blanket change — plain `load` (the semantics the
    /// per-UID overlay and ordinary test paths keep) still reads a
    /// group-writable file; only the daemon's strict call rejects it.
    #[test]
    fn plain_load_keeps_current_semantics_for_group_writable_files() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = strict_config_tree(root.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        let loaded = SystemConfig::load(&path).unwrap();
        assert!(
            !loaded.used_defaults,
            "plain load must keep its current read-anything semantics"
        );
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
        let config = SystemConfig::load(&path).unwrap().config;
        assert_eq!(config.daemon.interface_name, "protonwire0");
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
