//! LocalAgent requested-versus-applied feature reconciliation
//! (PRD T-20, FR-23E's honest-settings arm).
//!
//! ProtonWire REQUESTS a feature set in the LocalAgent connection
//! settings; the server APPLIES what it will (plan tier, server
//! capability, policy) and reports the applied set in
//! `AgentConnectionInfo.settings`, refusing some settings outright
//! via `LocalAgentSettingPolicyRefused` events. The daemon must never
//! report a feature as active when the server applied something else.
//!
//! [`FeatureReconciliation`] holds the requested set (updated on
//! every settings change) and folds in the applied set (every
//! `Connected` state's agent info) plus refusals, exposing
//! [`FeatureReconciliation::divergences`] — the requested-vs-applied
//! table the daemon surfaces to the frontend.

use crate::engine::{EngineAgentSettings, EngineNetshield, EngineSettingType};

/// One requested-vs-applied mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureDivergence {
    /// The setting that diverged.
    pub setting: EngineSettingType,
    /// What ProtonWire requested (never `None` — unset requests
    /// cannot diverge).
    pub requested: RequestedValue,
    /// What the server applied. `None` values mean the server did not
    /// report the setting — an UNCONFIRMED request, reported as a
    /// divergence of its own (the daemon must not assume agreement).
    pub applied: Option<RequestedValue>,
}

/// The comparable value of one setting (the engine mirror types are
/// small and `Copy`; this keeps the divergence self-describing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedValue {
    /// A boolean setting's value.
    Flag(bool),
    /// A Netshield level.
    Netshield(EngineNetshield),
}

/// The requested-versus-applied ledger (T-20).
#[derive(Debug, Clone)]
pub struct FeatureReconciliation {
    requested: EngineAgentSettings,
    applied: Option<EngineAgentSettings>,
    refused: Vec<EngineSettingType>,
}

impl FeatureReconciliation {
    /// A ledger opening with the connect-time request. Nothing is
    /// applied yet.
    pub fn new(requested: EngineAgentSettings) -> Self {
        Self {
            requested,
            applied: None,
            refused: Vec::new(),
        }
    }

    /// The request changed (connect or a live settings update): the
    /// previous applied snapshot no longer answers the new request.
    pub fn note_requested(&mut self, requested: EngineAgentSettings) {
        self.requested = requested;
        self.applied = None;
        self.refused.clear();
    }

    /// The server reported the applied set (a `Connected` state's
    /// agent info). Refusals recorded against the superseded request
    /// are stale — the new applied set is the answer.
    pub fn note_applied(&mut self, applied: EngineAgentSettings) {
        self.applied = Some(applied);
        self.refused.clear();
    }

    /// The server refused a setting outright.
    pub fn note_refused(&mut self, setting: EngineSettingType) {
        self.refused.push(setting);
    }

    /// The settings the server refused outright.
    pub fn refused(&self) -> &[EngineSettingType] {
        &self.refused
    }

    /// The requested-vs-applied table (T-20's deliverable). Every
    /// REQUESTED (Some) setting that the server did not apply with
    /// the same value is one entry; a request the server never
    /// answered reads as an unconfirmed divergence, not agreement.
    pub fn divergences(&self) -> Vec<FeatureDivergence> {
        let Some(applied) = &self.applied else {
            // Nothing applied yet: every requested setting is
            // unconfirmed (the connection is still negotiating — the
            // daemon must not report features as active).
            return self.unconfirmed_all();
        };
        let pairs = [
            (
                EngineSettingType::SplitTcp,
                self.requested.split_tcp.map(RequestedValue::Flag),
                applied.split_tcp.map(RequestedValue::Flag),
            ),
            (
                EngineSettingType::Netshield,
                self.requested
                    .netshield_level
                    .map(RequestedValue::Netshield),
                applied.netshield_level.map(RequestedValue::Netshield),
            ),
            (
                EngineSettingType::PortForwarding,
                self.requested.port_forwarding.map(RequestedValue::Flag),
                applied.port_forwarding.map(RequestedValue::Flag),
            ),
            (
                EngineSettingType::RandomNat,
                self.requested.random_nat.map(RequestedValue::Flag),
                applied.random_nat.map(RequestedValue::Flag),
            ),
        ];
        pairs
            .into_iter()
            .filter_map(|(setting, requested, applied_value)| {
                let requested_value = requested?; // unset requests cannot diverge
                (Some(requested_value) != applied_value).then_some(FeatureDivergence {
                    setting,
                    requested: requested_value,
                    applied: applied_value,
                })
            })
            .collect()
    }

    fn unconfirmed_all(&self) -> Vec<FeatureDivergence> {
        let mut out = Vec::new();
        if let Some(flag) = self.requested.split_tcp {
            out.push(self.unconfirmed(EngineSettingType::SplitTcp, RequestedValue::Flag(flag)));
        }
        if let Some(level) = self.requested.netshield_level {
            out.push(self.unconfirmed(
                EngineSettingType::Netshield,
                RequestedValue::Netshield(level),
            ));
        }
        if let Some(flag) = self.requested.port_forwarding {
            out.push(self.unconfirmed(
                EngineSettingType::PortForwarding,
                RequestedValue::Flag(flag),
            ));
        }
        if let Some(flag) = self.requested.random_nat {
            out.push(self.unconfirmed(EngineSettingType::RandomNat, RequestedValue::Flag(flag)));
        }
        out
    }

    fn unconfirmed(
        &self,
        setting: EngineSettingType,
        requested: RequestedValue,
    ) -> FeatureDivergence {
        FeatureDivergence {
            setting,
            requested,
            applied: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requested() -> EngineAgentSettings {
        EngineAgentSettings {
            split_tcp: Some(true),
            netshield_level: Some(EngineNetshield::AdsAndMalwareFilter),
            port_forwarding: Some(false),
            random_nat: Some(true),
            soft_jail: None,
            circumvention_routing: None,
        }
    }

    /// T-20's core: a matching applied set yields ZERO divergences —
    /// the daemon may report every requested feature as active.
    #[test]
    fn applied_matching_request_is_clean() {
        let mut ledger = FeatureReconciliation::new(requested());
        ledger.note_applied(requested());
        assert!(
            ledger.divergences().is_empty(),
            "identical applied set must reconcile clean, got {:?}",
            ledger.divergences()
        );
    }

    /// The applied set differs on netshield: one divergence naming
    /// the setting, the requested value, and the applied value.
    #[test]
    fn applied_netshield_downgrade_is_one_named_divergence() {
        let mut ledger = FeatureReconciliation::new(requested());
        let mut downgraded = requested();
        downgraded.netshield_level = Some(EngineNetshield::MalwareFilter);
        ledger.note_applied(downgraded);
        let divergences = ledger.divergences();
        assert_eq!(divergences.len(), 1, "only netshield moved");
        assert_eq!(
            divergences[0],
            FeatureDivergence {
                setting: EngineSettingType::Netshield,
                requested: RequestedValue::Netshield(EngineNetshield::AdsAndMalwareFilter),
                applied: Some(RequestedValue::Netshield(EngineNetshield::MalwareFilter)),
            }
        );
    }

    /// An unanswered request (applied field None) is an UNCONFIRMED
    /// divergence, never silent agreement.
    #[test]
    fn unanswered_request_is_unconfirmed_not_agreement() {
        let mut ledger = FeatureReconciliation::new(requested());
        let mut silent = requested();
        silent.netshield_level = None; // the server did not answer
        ledger.note_applied(silent);
        let divergences = ledger.divergences();
        assert_eq!(divergences.len(), 1, "unanswered ≠ agreed");
        assert_eq!(divergences[0].setting, EngineSettingType::Netshield);
        assert_eq!(divergences[0].applied, None, "the unconfirmed marker");
    }

    /// Before ANY applied set arrives, every requested setting is
    /// unconfirmed (negotiating ≠ active).
    #[test]
    fn no_applied_set_yet_means_all_requested_unconfirmed() {
        let ledger = FeatureReconciliation::new(requested());
        let divergences = ledger.divergences();
        assert_eq!(
            divergences.len(),
            4,
            "split_tcp + netshield + port_forwarding + random_nat"
        );
        assert!(
            divergences.iter().all(|d| d.applied.is_none()),
            "every request is unconfirmed while negotiating"
        );
    }

    /// Unset requests (None) never diverge: no preference, no claim.
    #[test]
    fn unset_requests_never_diverge() {
        let mut ledger = FeatureReconciliation::new(EngineAgentSettings::default());
        // The server applies values the client never requested —
        // still no divergence: an unset request makes no claim.
        ledger.note_applied(EngineAgentSettings {
            split_tcp: Some(true),
            netshield_level: Some(EngineNetshield::MalwareFilter),
            port_forwarding: Some(true),
            random_nat: Some(false),
            soft_jail: None,
            circumvention_routing: None,
        });
        assert!(
            ledger.divergences().is_empty(),
            "no preference means no divergence"
        );
    }

    /// A refusal is recorded and survives until the next applied set
    /// answers the request (refusals against a superseded request
    /// would be stale).
    #[test]
    fn refusals_are_recorded_and_cleared_by_new_answers() {
        let mut ledger = FeatureReconciliation::new(requested());
        ledger.note_refused(EngineSettingType::Netshield);
        assert_eq!(ledger.refused(), &[EngineSettingType::Netshield]);
        ledger.note_applied(requested());
        assert!(
            ledger.refused().is_empty(),
            "the applied set answers; the stale refusal clears"
        );
    }

    /// A settings update resets the ledger: the old applied set no
    /// longer answers the new request.
    #[test]
    fn requested_update_resets_applied_and_refusals() {
        let mut ledger = FeatureReconciliation::new(requested());
        ledger.note_applied(requested());
        assert!(ledger.divergences().is_empty());
        ledger.note_refused(EngineSettingType::SplitTcp);
        let mut updated = requested();
        updated.split_tcp = Some(false);
        ledger.note_requested(updated);
        assert!(
            ledger.refused().is_empty(),
            "refusals reset with the request"
        );
        let divergences = ledger.divergences();
        assert!(
            divergences.iter().all(|d| d.applied.is_none()),
            "nothing is confirmed against the NEW request yet"
        );
    }
}
