//! Per-UID user overlay: presentation preferences and per-user selectors
//! only (PRD section 10, M2 S11 / T-37). Any system-only key here is a
//! parse error by construction (`deny_unknown_fields` on every node), and
//! the per-user feature/profile fields are exactly the fields the system
//! document's authority table classifies [`Authority::PerUser`] — the
//! `overlay_peruser_fields_mirror_the_system_tables_peruser_set` test
//! pins the two tables against each other.
//!
//! S11's runtime loader: the daemon consults the overlay for the
//! REQUESTING peer's uid — the raw Unix credential integer, never a
//! client-supplied value — under a daemon-owned base
//! ([`PRODUCTION_OVERLAY_BASE`]). The root daemon never expands `~`,
//! derives a home directory, or follows a user-controlled config path
//! (PRD section 10: the client loads its own `$XDG_CONFIG_HOME` copy
//! and submits a typed overlay over IPC, and this loader is the
//! daemon-side revalidating half over daemon-store documents. The
//! typed submission wire is NOT landed — M2 shipped the load path
//! only, and the write path is the tracked post-M2 item 2). The
//! document is read
//! through the SAME hardened loader as the system configuration
//! ([`crate::yaml`]: anchors refused before parsing, size/depth/node
//! caps, duplicate-key rejection), and a PRESENT document that fails any
//! check is a hard error — only absence is the soft no-overlay state.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::Authority;
use super::SystemConfig;
use super::sections::{
    ConnectionType, KillSwitchMode, NatMode, NetShieldLevel, ProfileRanking, ProtocolMode,
    SplitTunnelMode,
};

/// The production per-UID overlay base: a daemon-owned tree under the
/// state root (`/var/lib/protonwire`, PRD section 10's runtime-state
/// path), each uid owning one document at
/// `<base>/<uid>/config.yaml` ([`overlay_path`]). Root-owned daemon
/// store, never a user home — see the module documentation.
pub const PRODUCTION_OVERLAY_BASE: &str = "/var/lib/protonwire/overlays";

/// Derives the per-UID overlay document path `<base>/<uid>/config.yaml`.
///
/// Path-safety is by construction: the uid is a raw `u32` credential
/// integer and `u32`'s `Display` emits decimal digits only, so the one
/// component inserted between `base` and `config.yaml` can never be
/// `.`, `..`, rooted, or carry a path separator — there is no string
/// surface to sanitize (pinned by
/// `overlay_path_is_derived_from_the_raw_uid_and_traversal_free`).
pub fn overlay_path(base: &Path, uid: u32) -> PathBuf {
    base.join(uid.to_string()).join("config.yaml")
}

/// The effective configuration for one uid: the system document with the
/// uid's overlay (if any) merged over it per the authority classes.
///
/// This is the daemon's request-time consult (SEC-27: after
/// peer-UID authentication; the uid is the requesting peer's — never
/// client-supplied). A missing overlay yields the system document
/// unchanged; a present-but-refused overlay propagates the error so the
/// caller answers fail-closed rather than serving a half-applied policy.
pub fn effective_config(
    system: &SystemConfig,
    base: &Path,
    uid: u32,
) -> Result<SystemConfig, OverlayError> {
    match UserOverlay::load_for_uid(base, uid)? {
        Some(overlay) => overlay.merged_over(system),
        None => Ok(system.clone()),
    }
}

/// Per-UID overlay loading and merging failures (S11). Every arm is
/// fail-closed: the caller must refuse to serve config-derived answers
/// from a document that failed any check — never fall back to a silent
/// system-only view the requesting user did not author.
#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    /// The document could not be read (absence is NOT this variant —
    /// only a missing file is the no-overlay state).
    #[error("failed to read the per-UID overlay from {path}: {source}")]
    Io {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O failure.
        source: std::io::Error,
    },
    /// The document failed the hardened YAML loader (parse, anchor
    /// policy, structural caps) or the overlay schema (an unknown key —
    /// including any system-authority key — is a parse error here).
    #[error(transparent)]
    Yaml(#[from] crate::yaml::YamlError),
    /// The document's own fields are inconsistent (schema generation).
    #[error("per-UID overlay validation failed:\n  - {}", violations.join("\n  - "))]
    Validation {
        /// Every violation, in document order.
        violations: Vec<String>,
    },
    /// The merged document violates the configuration's cross-field
    /// rules: the overlay is refused as a whole, never partially
    /// applied.
    #[error("overlay refused by the configuration's cross-field rules:\n  - {}",
        violations.join("\n  - "))]
    Merge {
        /// Every violated rule, in document order.
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
    /// Per-user feature requests (S11; every field optional — absent
    /// keeps the system value at merge).
    pub features: OverlayFeatures,
    /// Per-user default-profile selectors (S11).
    pub profiles: OverlayProfiles,
}

impl UserOverlay {
    /// Field-level authority report for the overlay document (T-37
    /// groundwork): every field of the typed surface carries exactly one
    /// entry, and every overlay field is per-user by construction — the
    /// document itself only allows presentation preferences and
    /// selectors, so no entry can be `System` without the schema
    /// contradicting itself (the system document's table is the mirror
    /// image: none of its `System` fields may appear here, and the
    /// `overlay_peruser_fields_mirror_the_system_tables_peruser_set`
    /// test pins that its `PerUser` set is exactly this document's
    /// feature/profile fields).
    pub fn authority_report(&self) -> Vec<(&'static str, Authority)> {
        vec![
            ("schema_version", Authority::PerUser),
            ("presentation.default_output", Authority::PerUser),
            ("features.secure_core", Authority::PerUser),
            ("features.kill_switch", Authority::PerUser),
            ("features.split_tunnel", Authority::PerUser),
            ("features.netshield", Authority::PerUser),
            ("features.port_forwarding", Authority::PerUser),
            ("features.nat", Authority::PerUser),
            ("features.vpn_accelerator", Authority::PerUser),
            ("profiles.default.connection_type", Authority::PerUser),
            ("profiles.default.protocol", Authority::PerUser),
            ("profiles.default.selection.mode", Authority::PerUser),
            ("profiles.default.selection.by", Authority::PerUser),
            (
                "profiles.default.selection.exclude_countries",
                Authority::PerUser,
            ),
            ("profiles.default.selection.require", Authority::PerUser),
        ]
    }

    /// Validates the overlay's own fields: the schema generation must
    /// match the system document's (`schema_version` defaults to 0 when
    /// absent, so a version-less document is refused here too).
    pub fn validate(&self) -> Result<(), OverlayError> {
        let mut violations = Vec::new();
        if self.schema_version != SystemConfig::EXPECTED_SCHEMA_VERSION {
            violations.push(format!(
                "schema_version must be {} (found {})",
                SystemConfig::EXPECTED_SCHEMA_VERSION,
                self.schema_version
            ));
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(OverlayError::Validation { violations })
        }
    }

    /// Loads the overlay document for `uid` under the daemon-owned
    /// `base` (S11): `<base>/<uid>/config.yaml` through the hardened
    /// loader.
    ///
    /// Only absence is soft (`Ok(None)` — the no-overlay state; the
    /// system document stands unchanged). A PRESENT document that fails
    /// ANY check — the anchor policy, size/depth caps, the overlay
    /// schema (`deny_unknown_fields` refuses every system-authority key,
    /// which is T-37's rejection of system-only fields), or the schema
    /// generation — is a hard [`OverlayError`]: fail-closed, never a
    /// silent system-only fallback for a document the user did author.
    pub fn load_for_uid(base: &Path, uid: u32) -> Result<Option<Self>, OverlayError> {
        let path = overlay_path(base, uid);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(source) => return Err(OverlayError::Io { path, source }),
        };
        let overlay: Self = crate::yaml::from_slice(&bytes)?;
        overlay.validate()?;
        Ok(Some(overlay))
    }

    /// Merges this overlay over `system` per the S3 authority classes
    /// (S11): each PRESENT per-user field replaces the system value
    /// (per-field overwrite depth); absent fields keep it; system fields
    /// are untouched by construction (the overlay cannot express them).
    ///
    /// Administrator floors (SEC-27 / acceptance list #26): a system
    /// document that pins `features.kill_switch: permanent` keeps it —
    /// the PRD's named "permanent kill-switch floor". That is the only
    /// floor: with the shipped default (`on`) a user may still lower the
    /// switch, because `config set kill-switch off` is FR-56's grammar
    /// and only the administrator's explicit `permanent` is a floor.
    ///
    /// The merged document is re-validated: the cross-field rules
    /// (`validate`) bind the EFFECTIVE configuration, so an overlay that
    /// is individually valid but incompatible with the system values
    /// (port forwarding over moderate NAT) is refused as a whole with
    /// every violation named — never partially applied.
    pub fn merged_over(&self, system: &SystemConfig) -> Result<SystemConfig, OverlayError> {
        let mut effective = system.clone();
        let features = &self.features;
        if let Some(value) = features.secure_core {
            effective.features.secure_core = value;
        }
        if let Some(value) = features.kill_switch {
            effective.features.kill_switch = value;
        }
        if system.features.kill_switch == KillSwitchMode::Permanent {
            // The administrator's permanent kill switch outranks any
            // overlay request (PRD section 10's named floor).
            effective.features.kill_switch = KillSwitchMode::Permanent;
        }
        if let Some(value) = features.split_tunnel {
            effective.features.split_tunnel = value;
        }
        if let Some(value) = features.netshield {
            effective.features.netshield = value;
        }
        if let Some(value) = features.port_forwarding {
            effective.features.port_forwarding = value;
        }
        if let Some(value) = features.nat {
            effective.features.nat = value;
        }
        if let Some(value) = features.vpn_accelerator {
            effective.features.vpn_accelerator = value;
        }
        let default = &self.profiles.default;
        if let Some(value) = default.connection_type {
            effective.profiles.default.connection_type = value;
        }
        if let Some(value) = default.protocol {
            effective.profiles.default.protocol = value;
        }
        if let Some(value) = default.selection.mode.clone() {
            effective.profiles.default.selection.mode = value;
        }
        if let Some(value) = default.selection.by {
            effective.profiles.default.selection.by = value;
        }
        if let Some(value) = default.selection.exclude_countries.clone() {
            effective.profiles.default.selection.exclude_countries = value;
        }
        if let Some(value) = default.selection.require.clone() {
            effective.profiles.default.selection.require = value;
        }
        // The cross-field rules bind the effective document; a violation
        // refuses the whole merge. `validate` only ever returns the
        // Validation variant — the catch-all is defensive depth.
        match effective.validate() {
            Ok(()) => Ok(effective),
            Err(super::ConfigLoadError::Validation { violations }) => {
                Err(OverlayError::Merge { violations })
            }
            Err(other) => Err(OverlayError::Merge {
                violations: vec![other.to_string()],
            }),
        }
    }
}

/// Presentation preferences.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UserPresentation {
    /// Default CLI output format.
    pub default_output: Option<OutputFormat>,
}

/// Per-user feature requests (S11): each field overrides the system
/// document's default for the requesting UID when present; the closed
/// vocabularies ARE the administrator ceilings (an out-of-vocabulary
/// request is a parse error, and the cross-field rules are re-checked on
/// the merged document — see [`UserOverlay::merged_over`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OverlayFeatures {
    /// Secure Core requested.
    pub secure_core: Option<bool>,
    /// Kill switch mode (subject to the permanent kill-switch floor).
    pub kill_switch: Option<KillSwitchMode>,
    /// Split tunnel mode.
    pub split_tunnel: Option<SplitTunnelMode>,
    /// NetShield level.
    pub netshield: Option<NetShieldLevel>,
    /// Port forwarding requested.
    pub port_forwarding: Option<bool>,
    /// NAT mode.
    pub nat: Option<NatMode>,
    /// VPN Accelerator requested.
    pub vpn_accelerator: Option<bool>,
}

/// Per-user default-profile selectors (S11).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OverlayProfiles {
    /// The per-user default profile template.
    pub default: OverlayProfileDefault,
}

/// The per-user default profile (S11).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OverlayProfileDefault {
    /// Profile connection type.
    pub connection_type: Option<ConnectionType>,
    /// Protocol.
    pub protocol: Option<ProtocolMode>,
    /// Selection defaults.
    pub selection: OverlayProfileSelection,
}

/// The per-user default profile's selection (S11).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OverlayProfileSelection {
    /// Selection mode.
    pub mode: Option<String>,
    /// Ranking policy.
    pub by: Option<ProfileRanking>,
    /// Excluded countries.
    pub exclude_countries: Option<Vec<String>>,
    /// Required features.
    pub require: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ------------------------------------------------------------------
    // M2 S11: the per-user FEATURE and PROFILE sections (PRD section 10:
    // overlays are allowlisted to "per-UID profiles, selectors,
    // presentation preferences, and feature requests within
    // administrator-defined ceilings"). Red evidence for the two parse
    // tests is behavioral: against the S3 surface, `features:` and
    // `profiles:` are unknown keys and `deny_unknown_fields` refuses the
    // whole document (run on this commit's parent to reproduce).
    // ------------------------------------------------------------------

    /// Every feature field parses, absent fields stay `None`, and the
    /// section is optional as a whole. Red evidence (behavioral,
    /// observed at the red stage): against the S3 surface `features:` is
    /// an unknown key and `deny_unknown_fields` refuses the document.
    #[test]
    fn overlay_features_section_parses() {
        let parsed = crate::yaml::from_str::<UserOverlay>(
            "schema_version: 2\nfeatures:\n  secure_core: true\n  kill_switch: permanent\n  \
             split_tunnel: exclude\n  netshield: malware\n  port_forwarding: true\n  nat: moderate\n\
             \x20 vpn_accelerator: false\n",
        )
        .expect("a per-user features document must parse");
        let features = &parsed.features;
        assert_eq!(features.secure_core, Some(true));
        assert_eq!(features.kill_switch, Some(KillSwitchMode::Permanent));
        assert_eq!(features.split_tunnel, Some(SplitTunnelMode::Exclude));
        assert_eq!(features.netshield, Some(NetShieldLevel::Malware));
        assert_eq!(features.port_forwarding, Some(true));
        assert_eq!(features.nat, Some(NatMode::Moderate));
        assert_eq!(features.vpn_accelerator, Some(false));
        // The presentation/profile arms are untouched by a features-only
        // document (per-section independence).
        assert_eq!(parsed.presentation.default_output, None);
        assert_eq!(parsed.profiles.default.connection_type, None);

        // Absent fields parse as None (the merge treats None as "keep the
        // system value").
        let parsed = crate::yaml::from_str::<UserOverlay>(
            "schema_version: 2\nfeatures:\n  kill_switch: off\n",
        )
        .expect("a sparse features section must parse");
        assert_eq!(parsed.features.kill_switch, Some(KillSwitchMode::Off));
        assert_eq!(parsed.features.secure_core, None);
    }

    /// The per-user default-profile selectors parse (PRD section 10:
    /// overlays carry per-UID profiles and selectors). Red evidence
    /// (behavioral): `profiles:` was an unknown key on the S3 surface.
    #[test]
    fn overlay_profiles_section_parses() {
        let parsed = crate::yaml::from_str::<UserOverlay>(
            "schema_version: 2\nprofiles:\n  default:\n    connection_type: p2p\n    \
             protocol: stealth\n    selection:\n      mode: fastest\n      by: latency\n      \
             exclude_countries: [US, IS]\n      require: [tor]\n",
        )
        .expect("a per-user profile document must parse");
        let default = &parsed.profiles.default;
        assert_eq!(default.connection_type, Some(ConnectionType::P2p));
        assert_eq!(default.protocol, Some(ProtocolMode::Stealth));
        assert_eq!(default.selection.mode.as_deref(), Some("fastest"));
        assert_eq!(default.selection.by, Some(ProfileRanking::Latency));
        assert_eq!(
            default.selection.exclude_countries,
            Some(vec!["US".to_owned(), "IS".to_owned()])
        );
        assert_eq!(default.selection.require, Some(vec!["tor".to_owned()]));
        // The features arm is untouched by a profiles-only document.
        assert_eq!(parsed.features.kill_switch, None);
    }

    /// PRD section 10's closing rule, held on the overlay surface too:
    /// `lan.policy` is the sole global LAN setting, so no
    /// `features.lan_access` alias may exist HERE either — an unknown key
    /// inside the feature section is a parse error naming it.
    #[test]
    fn overlay_features_refuse_unknown_and_alias_fields() {
        let err = crate::yaml::from_str::<UserOverlay>(
            "schema_version: 2\nfeatures:\n  lan_access: true\n",
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("lan_access"),
            "must name the unknown key: {msg}"
        );

        let err = crate::yaml::from_str::<UserOverlay>(
            "schema_version: 2\nprofiles:\n  default:\n    connection_type: standard\n    \
             lan_policy: allow\n",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("lan_policy"),
            "must name the unknown key: {}",
            err
        );
    }

    /// The feature vocabularies are the administrator ceilings: an
    /// out-of-vocabulary value is a PARSE error. The `vocabulary!`
    /// types (S3) name the config field path AND every accepted
    /// spelling; the plain kebab-case enums (`kill_switch`) name every
    /// accepted spelling through serde's own message (the S3 division —
    /// both refuse at parse, never validate).
    #[test]
    fn overlay_feature_vocabularies_enforced() {
        let err = crate::yaml::from_str::<UserOverlay>(
            "schema_version: 2\nfeatures:\n  kill_switch: sometimes\n",
        )
        .unwrap_err();
        let msg = err.to_string();
        for spelling in ["`off`", "`on`", "`permanent`"] {
            assert!(msg.contains(spelling), "must name {spelling}: {msg}");
        }

        let err = crate::yaml::from_str::<UserOverlay>(
            "schema_version: 2\nprofiles:\n  default:\n    selection:\n      by: speed\n",
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("profiles.default.selection.by"),
            "must name the field: {msg}"
        );
        // FR-19: a `speed` ranking is refused with the accepted spellings.
        for spelling in ["official", "balanced", "load", "latency"] {
            assert!(msg.contains(spelling), "must name `{spelling}`: {msg}");
        }
    }

    /// S3/T-37 coherence pin: the per-user fields the overlay CAN express
    /// are exactly the fields the system document's authority table
    /// classifies `PerUser` — no more (an overlay field with no PerUser
    /// entry would be unclassified authority) and no fewer (a PerUser
    /// field the overlay cannot express would be dead classification).
    #[test]
    fn overlay_peruser_fields_mirror_the_system_tables_peruser_set() {
        use crate::SystemConfig;
        let system = SystemConfig::default();
        let system_per_user: std::collections::BTreeSet<&str> = system
            .authority_report()
            .into_iter()
            .filter(|(_, authority)| *authority == super::Authority::PerUser)
            .map(|(path, _)| path)
            .collect();
        let overlay: std::collections::BTreeSet<&str> = UserOverlay::default()
            .authority_report()
            .into_iter()
            .map(|(path, _)| path)
            .collect();
        // The overlay's own two non-system fields (its schema version and
        // the presentation preference, which the system document does not
        // carry) are the only additions.
        let difference: Vec<&str> = overlay.difference(&system_per_user).copied().collect();
        assert_eq!(
            difference,
            vec!["presentation.default_output", "schema_version"],
            "the overlay may express exactly the system table's PerUser fields \
             plus its own version and presentation"
        );
        let missing: Vec<&str> = system_per_user.difference(&overlay).copied().collect();
        assert!(
            missing.is_empty(),
            "every PerUser-classified system field must be expressible in the \
             overlay: {missing:?}"
        );
    }

    /// T-37 groundwork: the overlay's authority table covers every field
    /// of its typed surface and every entry is per-user. Red evidence is
    /// the disclosed compile-red (`UserOverlay::authority_report` did not
    /// exist on this commit's parent); the S11 extension (features and
    /// profiles) is enforced the same way — the maximal fixture below
    /// fails coverage if a new field lands without its table entry.
    #[test]
    fn overlay_authority_report_covers_every_typed_field() {
        let overlay = UserOverlay {
            schema_version: 2,
            presentation: UserPresentation {
                default_output: Some(OutputFormat::Json),
            },
            features: OverlayFeatures {
                secure_core: Some(true),
                kill_switch: Some(KillSwitchMode::Permanent),
                split_tunnel: Some(SplitTunnelMode::Exclude),
                netshield: Some(NetShieldLevel::Malware),
                port_forwarding: Some(true),
                nat: Some(NatMode::Moderate),
                vpn_accelerator: Some(false),
            },
            profiles: OverlayProfiles {
                default: OverlayProfileDefault {
                    connection_type: Some(ConnectionType::P2p),
                    protocol: Some(ProtocolMode::Stealth),
                    selection: OverlayProfileSelection {
                        mode: Some("fastest".to_owned()),
                        by: Some(ProfileRanking::Latency),
                        exclude_countries: Some(vec!["US".to_owned()]),
                        require: Some(vec!["tor".to_owned()]),
                    },
                },
            },
        };
        let rendered = serde_norway::to_value(&overlay).unwrap();
        let report = overlay.authority_report();
        let mut leaves = Vec::new();
        walk_leaf_paths(&rendered, "", &report, &mut leaves);
        assert!(!leaves.is_empty(), "the walk must find the overlay fields");

        for leaf in &leaves {
            let entries: Vec<_> = report
                .iter()
                .filter(|(path, _)| *path == leaf.as_str())
                .collect();
            assert_eq!(
                entries.len(),
                1,
                "field {leaf} must carry exactly one authority entry (found {})",
                entries.len()
            );
        }
        for (path, authority) in &report {
            assert_eq!(
                *authority,
                Authority::PerUser,
                "overlay field {path} must be per-user"
            );
        }
    }

    // ------------------------------------------------------------------
    // M2 S11: the per-UID overlay LOADER and MERGE (T-37's authority
    // path). Red-evidence class for this block: COMPILE-RED (disclosed)
    // — `overlay_path`, `load_for_uid`, `merged_over`, and
    // `effective_config` did not exist on this commit's parent, so the
    // suite could not build until the loader landed. The behavioral
    // layers underneath (anchor refusal, size/depth caps, duplicate-key
    // rejection, deny_unknown_fields) are already proven by the yaml and
    // S3 suites; the tests here pin that the overlay path goes THROUGH
    // them and that the merge obeys the authority table.
    // ------------------------------------------------------------------

    /// Plants one overlay document for `uid` under `base` and returns
    /// the exact path written.
    fn plant_overlay(base: &std::path::Path, uid: u32, document: &str) -> std::path::PathBuf {
        let dir = base.join(uid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        std::fs::write(&path, document).unwrap();
        path
    }

    /// Path derivation (UID provenance, the store half): the per-UID
    /// document lives at `<base>/<uid>/config.yaml`, and the uid is a
    /// RAW credential integer — `u32`'s `Display` emits decimal digits
    /// only, so the single inserted component can never be `.`, `..`,
    /// absolute, or carry a separator: the path is traversal-free and
    /// injection-free BY CONSTRUCTION, and this test pins that property
    /// (any component-level trick would have to come from the integer
    /// formatting itself).
    #[test]
    fn overlay_path_is_derived_from_the_raw_uid_and_traversal_free() {
        let base = std::path::Path::new("/var/lib/protonwire/overlays");
        for uid in [0, 1, 1000, 42, u32::MAX] {
            let path = super::overlay_path(base, uid);
            assert_eq!(
                path,
                base.join(uid.to_string()).join("config.yaml"),
                "uid {uid}"
            );
            // The uid component is exactly its decimal rendering — all
            // digits, never a relative or escaping component.
            let uid_segment = path
                .parent()
                .and_then(|dir| dir.file_name())
                .and_then(|name| name.to_str())
                .unwrap_or_else(|| panic!("uid {uid}: no uid segment in {}", path.display()));
            assert_eq!(uid_segment, uid.to_string());
            assert!(
                uid_segment.chars().all(|c| c.is_ascii_digit()),
                "uid {uid}: segment {uid_segment:?} must be decimal digits only"
            );
            assert_ne!(uid_segment, ".");
            assert_ne!(uid_segment, "..");
            // No component of the derived tail may be relative.
            for component in path.components() {
                assert!(
                    !matches!(
                        component,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    ),
                    "uid {uid}: relative component in {}",
                    path.display()
                );
            }
        }
        // Distinct uids never collide (another UID's overlay is another
        // document — the namespace pin's path half).
        assert_ne!(
            super::overlay_path(base, 1000),
            super::overlay_path(base, 1001)
        );
    }

    /// The no-overlay default (S11 red list): an absent base, an absent
    /// per-UID directory, and a present directory with no document all
    /// yield `None` — the system configuration stands unchanged for
    /// that uid.
    #[test]
    fn load_for_uid_without_an_overlay_yields_none() {
        let base = tempfile::tempdir().unwrap();
        // Nothing exists at all.
        assert!(
            UserOverlay::load_for_uid(&base.path().join("absent"), 1000)
                .unwrap()
                .is_none()
        );
        // Base exists, the uid's directory does not.
        assert!(
            UserOverlay::load_for_uid(base.path(), 1000)
                .unwrap()
                .is_none(),
            "an absent per-UID directory is the no-overlay state"
        );
        // The uid's directory exists but holds no document.
        std::fs::create_dir_all(base.path().join("1000")).unwrap();
        assert!(
            UserOverlay::load_for_uid(base.path(), 1000)
                .unwrap()
                .is_none(),
            "an absent document is the no-overlay state"
        );
    }

    /// The loader reads THE REQUESTING UID's document — one base, two
    /// uids, one document: only the matching uid sees it.
    #[test]
    fn load_for_uid_reads_only_the_requesting_users_document() {
        let base = tempfile::tempdir().unwrap();
        plant_overlay(
            base.path(),
            1000,
            "schema_version: 2\nfeatures:\n  netshield: off\npresentation:\n  default_output: json\n",
        );
        let mine = UserOverlay::load_for_uid(base.path(), 1000)
            .unwrap()
            .expect("uid 1000's overlay must load");
        assert_eq!(mine.features.netshield, Some(NetShieldLevel::Off));
        assert_eq!(mine.presentation.default_output, Some(OutputFormat::Json));
        // A different peer uid reads a different (absent) document.
        assert!(
            UserOverlay::load_for_uid(base.path(), 1001)
                .unwrap()
                .is_none(),
            "uid 1001 must not see uid 1000's overlay"
        );
    }

    /// T-37's rejection of system-only fields, at the LOADER: every
    /// top-level section the system document owns is refused inside an
    /// overlay document — the refusal names the section (the
    /// `deny_unknown_fields` construction; this pins it for EVERY
    /// system-owned section through the per-UID load path).
    #[test]
    fn load_for_uid_refuses_every_system_authority_section() {
        let base = tempfile::tempdir().unwrap();
        for section in [
            "daemon",
            "account",
            "server_selection",
            "connection_groups",
            "connection",
            "dns",
            "lan",
            "split_tunnel",
            "auto_connect",
        ] {
            plant_overlay(
                base.path(),
                1000,
                &format!("schema_version: 2\n{section}: {{}}\n"),
            );
            let err = UserOverlay::load_for_uid(base.path(), 1000)
                .expect_err("a system-authority section must be refused");
            assert!(
                err.to_string().contains(section),
                "the refusal must name `{section}`: {err}"
            );
        }
    }

    /// T-36 discipline through the overlay path: an overlay carrying an
    /// anchor is REFUSED by the hardened loader's scanner policy, never
    /// parsed around.
    #[test]
    fn load_for_uid_refuses_anchors() {
        let base = tempfile::tempdir().unwrap();
        plant_overlay(
            base.path(),
            1000,
            "schema_version: 2\nfeatures: &f\n  kill_switch: off\n",
        );
        let err = UserOverlay::load_for_uid(base.path(), 1000)
            .expect_err("an anchored overlay document must be refused");
        assert!(
            err.to_string().to_lowercase().contains("anchor"),
            "must name the anchor policy: {err}"
        );
    }

    /// The overlay document carries the same schema generation as the
    /// system document: a wrong (or missing — `default` yields 0)
    /// `schema_version` is a validation error naming the field.
    #[test]
    fn load_for_uid_refuses_a_wrong_schema_version() {
        let base = tempfile::tempdir().unwrap();
        plant_overlay(
            base.path(),
            1000,
            "schema_version: 1\nfeatures:\n  nat: strict\n",
        );
        let err = UserOverlay::load_for_uid(base.path(), 1000)
            .expect_err("a wrong schema version must be refused");
        assert!(
            err.to_string().contains("schema_version"),
            "must name the field: {err}"
        );

        plant_overlay(base.path(), 1000, "features:\n  nat: strict\n");
        let err = UserOverlay::load_for_uid(base.path(), 1000)
            .expect_err("a missing schema version must be refused");
        assert!(
            err.to_string().contains("schema_version"),
            "must name the field: {err}"
        );
    }

    /// A PRESENT but unreadable overlay is a hard error naming the path
    /// and the underlying failure — never a silent no-overlay
    /// (the system loader's V4 discipline, mirrored; absence is the only
    /// soft arm). Mirrors the suite's non-root-only permission pattern.
    #[test]
    fn load_for_uid_unreadable_overlay_is_a_hard_error() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let closed = base.path().join("1000");
        std::fs::create_dir_all(&closed).unwrap();
        std::fs::write(closed.join("config.yaml"), "schema_version: 2\n").unwrap();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let outcome = UserOverlay::load_for_uid(base.path(), 1000);
        let provable = std::fs::read(closed.join("config.yaml")).is_err();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
        if !provable {
            return; // running as root: the mode bits deny nothing
        }
        let err = outcome.expect_err("an unreadable overlay must be a hard error");
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

    /// Merge semantics (per-field overwrite depth, the apply half): a
    /// present overlay field replaces the system value; an absent field
    /// keeps it. Every PerUser field is exercised.
    #[test]
    fn merged_over_applies_every_per_user_field() {
        use crate::SystemConfig;
        let mut system = SystemConfig::default();
        // Distinguishable system-side per-user values, so "the overlay
        // value landed" is provable against a non-default baseline.
        system.features.secure_core = false;
        system.features.kill_switch = KillSwitchMode::On;
        system.features.split_tunnel = SplitTunnelMode::Off;
        system.features.netshield = NetShieldLevel::AdsTrackersMalware;
        system.features.port_forwarding = false;
        system.features.nat = NatMode::Strict;
        system.features.vpn_accelerator = true;
        system.profiles.default.connection_type = ConnectionType::Standard;
        system.profiles.default.protocol = ProtocolMode::Smart;
        system.profiles.default.selection.mode = "fastest".into();
        system.profiles.default.selection.by = ProfileRanking::Official;
        system.profiles.default.selection.exclude_countries = vec!["IS".into()];
        system.profiles.default.selection.require = vec!["p2p".into()];

        let overlay = crate::yaml::from_str::<UserOverlay>(
            "schema_version: 2\nfeatures:\n  secure_core: true\n  kill_switch: permanent\n  \
             split_tunnel: include\n  netshield: off\n  port_forwarding: true\n  nat: strict\n  \
             vpn_accelerator: false\nprofiles:\n  default:\n    connection_type: tor\n    \
             protocol: stealth\n    selection:\n      mode: random\n      by: load\n      \
             exclude_countries: [US]\n      require: [secure-core]\n",
        )
        .unwrap();
        let merged = overlay.merged_over(&system).unwrap();

        assert!(merged.features.secure_core);
        assert_eq!(merged.features.kill_switch, KillSwitchMode::Permanent);
        assert_eq!(merged.features.split_tunnel, SplitTunnelMode::Include);
        assert_eq!(merged.features.netshield, NetShieldLevel::Off);
        assert!(merged.features.port_forwarding);
        assert_eq!(merged.features.nat, NatMode::Strict);
        assert!(!merged.features.vpn_accelerator);
        assert_eq!(merged.profiles.default.connection_type, ConnectionType::Tor);
        assert_eq!(merged.profiles.default.protocol, ProtocolMode::Stealth);
        assert_eq!(merged.profiles.default.selection.mode, "random");
        assert_eq!(merged.profiles.default.selection.by, ProfileRanking::Load);
        assert_eq!(
            merged.profiles.default.selection.exclude_countries,
            vec!["US".to_owned()]
        );
        assert_eq!(
            merged.profiles.default.selection.require,
            vec!["secure-core".to_owned()]
        );

        // The keep-half: an empty overlay changes nothing (the no-overlay
        // default expressed through the merge itself).
        let empty = crate::yaml::from_str::<UserOverlay>("schema_version: 2\n").unwrap();
        let merged = empty.merged_over(&system).unwrap();
        assert_eq!(merged.features.kill_switch, KillSwitchMode::On);
        assert_eq!(
            merged.features.netshield,
            NetShieldLevel::AdsTrackersMalware
        );
    }

    /// Resolves a dotted authority path in a serialized document. Paths
    /// carrying the sequence-element form (`rules[].domain`) resolve at
    /// their containing sequence (the first `[]` boundary) — comparing
    /// the whole sequence still compares every element field.
    fn resolve<'a>(value: &'a serde_norway::Value, path: &str) -> Option<&'a serde_norway::Value> {
        let mut current = value;
        for segment in path.split("[]").next().unwrap_or("").split('.') {
            current = current.get(segment)?;
        }
        Some(current)
    }

    /// THE authority pin (T-37): after a merge, every field the system
    /// table classifies `System` is bit-identical to the system
    /// document's value — the overlay physically cannot express them,
    /// and the merge never touches them. The comparison walks the whole
    /// authority table against serialized documents, so a future field
    /// added to the table is automatically covered.
    #[test]
    fn merged_over_preserves_every_system_authority_field() {
        use crate::SystemConfig;
        let mut system = SystemConfig::default();
        system.features.port_forwarding = true; // a non-default system doc
        let overlay = crate::yaml::from_str::<UserOverlay>(
            "schema_version: 2\nfeatures:\n  kill_switch: permanent\n  netshield: off\n",
        )
        .unwrap();
        let merged = overlay.merged_over(&system).unwrap();

        let system_value = serde_norway::to_value(&system).unwrap();
        let merged_value = serde_norway::to_value(&merged).unwrap();
        let mut system_fields = 0;
        for (path, authority) in system.authority_report() {
            if authority != Authority::System {
                continue;
            }
            system_fields += 1;
            assert_eq!(
                resolve(&system_value, path),
                resolve(&merged_value, path),
                "system-authority field {path} changed across the merge"
            );
        }
        assert!(
            system_fields > 50,
            "the walk must cover the system table (found {system_fields})"
        );
    }

    /// The administrator floor the PRD names (section 10: overlays
    /// cannot change the "permanent kill-switch floor"; acceptance list
    /// #26: overlays cannot weaken administrator floors): a system
    /// document that pins `features.kill_switch: permanent` keeps it —
    /// any overlay request below permanent is overridden. The honest
    /// complement: with the admin at the DEFAULT (`on`), a user overlay
    /// MAY lower it — `config set kill-switch off` is FR-56's grammar,
    /// so only the admin's explicit `permanent` is a floor.
    #[test]
    fn merged_over_enforces_the_permanent_kill_switch_floor() {
        use crate::SystemConfig;
        let mut system = SystemConfig::default();
        system.features.kill_switch = KillSwitchMode::Permanent;
        for requested in ["off", "on", "permanent"] {
            let overlay = crate::yaml::from_str::<UserOverlay>(&format!(
                "schema_version: 2\nfeatures:\n  kill_switch: {requested}\n"
            ))
            .unwrap();
            let merged = overlay.merged_over(&system).unwrap();
            assert_eq!(
                merged.features.kill_switch,
                KillSwitchMode::Permanent,
                "an admin-pinned permanent kill switch outranks `{requested}`"
            );
        }
        // No kill_switch request at all: the system value stands.
        let empty = crate::yaml::from_str::<UserOverlay>("schema_version: 2\n").unwrap();
        assert_eq!(
            empty.merged_over(&system).unwrap().features.kill_switch,
            KillSwitchMode::Permanent
        );

        // The complement: the admin default is `on`, not a floor.
        let default_system = SystemConfig::default();
        assert_eq!(
            default_system.features.kill_switch,
            KillSwitchMode::On,
            "the shipped default must be on for this arm to mean anything"
        );
        let lower = crate::yaml::from_str::<UserOverlay>(
            "schema_version: 2\nfeatures:\n  kill_switch: off\n",
        )
        .unwrap();
        assert_eq!(
            lower
                .merged_over(&default_system)
                .unwrap()
                .features
                .kill_switch,
            KillSwitchMode::Off,
            "a user may lower a non-permanent kill switch (FR-56's off grammar)"
        );
    }

    /// Cross-field rules bind the EFFECTIVE document: an overlay that is
    /// individually valid but incompatible with the system values
    /// (port forwarding with moderate NAT) is refused as a whole —
    /// every violation is named, nothing is partially applied.
    #[test]
    fn merged_over_refuses_a_cross_field_violation() {
        use crate::SystemConfig;
        let system = SystemConfig::default(); // nat: strict (default)
        let overlay = crate::yaml::from_str::<UserOverlay>(
            "schema_version: 2\nfeatures:\n  port_forwarding: true\n  nat: moderate\n",
        )
        .unwrap();
        let err = overlay
            .merged_over(&system)
            .expect_err("port forwarding over moderate NAT must be refused");
        let message = err.to_string();
        assert!(
            message.contains("port_forwarding") && message.contains("moderate"),
            "must name the violated rules: {message}"
        );

        // The individually-valid parts of a refused overlay do NOT land:
        // rerun the same overlay with only the conflicting pair removed
        // and confirm the surviving field applies — the refusal above
        // was the merge refusing, not the system document changing.
        let ok = crate::yaml::from_str::<UserOverlay>(
            "schema_version: 2\nfeatures:\n  port_forwarding: true\n",
        )
        .unwrap();
        assert!(ok.merged_over(&system).unwrap().features.port_forwarding);
    }

    /// The consult convenience: with no overlay for the uid, the
    /// effective config is the system document, value-for-value.
    #[test]
    fn effective_config_without_an_overlay_is_the_system_document() {
        use crate::SystemConfig;
        let system = SystemConfig::default();
        let base = tempfile::tempdir().unwrap();
        let effective =
            super::effective_config(&system, &base.path().join("absent"), 1000).unwrap();
        assert_eq!(
            serde_norway::to_value(&effective).unwrap(),
            serde_norway::to_value(&system).unwrap(),
            "no overlay must leave the system document unchanged"
        );
        effective.validate().unwrap();
    }

    /// Walks every leaf field path of a serialized document (mirrors the
    /// system-document walker in the parent module's tests).
    fn walk_leaf_paths(
        value: &serde_norway::Value,
        prefix: &str,
        report: &[(&'static str, Authority)],
        out: &mut Vec<String>,
    ) {
        match value {
            serde_norway::Value::Mapping(mapping) => {
                if !prefix.is_empty() && report.iter().any(|(path, _)| *path == prefix) {
                    out.push(prefix.to_owned());
                    return;
                }
                for (key, val) in mapping {
                    let key = key.as_str().expect("overlay keys serialize as strings");
                    let path = if prefix.is_empty() {
                        key.to_owned()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    walk_leaf_paths(val, &path, report, out);
                }
            }
            serde_norway::Value::Sequence(sequence) => {
                let of_mappings = !sequence.is_empty()
                    && sequence
                        .iter()
                        .all(|element| matches!(element, serde_norway::Value::Mapping(_)));
                if of_mappings {
                    for element in sequence {
                        walk_leaf_paths(element, &format!("{prefix}[]"), report, out);
                    }
                } else {
                    out.push(prefix.to_owned());
                }
            }
            _ => out.push(prefix.to_owned()),
        }
    }
}
