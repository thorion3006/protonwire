//! Per-UID user overlay: presentation preferences and per-user selectors
//! only (PRD section 10, M2 S11 / T-37). Any system-only key here is a
//! parse error by construction (`deny_unknown_fields` on every node), and
//! the per-user feature/profile fields are exactly the fields the system
//! document's authority table classifies [`Authority::PerUser`] — the
//! `overlay_peruser_fields_mirror_the_system_tables_peruser_set` test
//! pins the two tables against each other.

use serde::{Deserialize, Serialize};

use super::Authority;
use super::sections::{
    ConnectionType, KillSwitchMode, NatMode, NetShieldLevel, ProfileRanking, ProtocolMode,
    SplitTunnelMode,
};

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
        assert!(msg.contains("lan_access"), "must name the unknown key: {msg}");

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
