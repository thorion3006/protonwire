//! Bounded on-demand latency probing (T-34, FR-18/FR-19B).
//!
//! The PLANNER is pure: given a shortlist of logical ids (never the
//! full catalog — FR-18), prior observations, and the budget state, it
//! decides WHICH endpoints to probe NOW and which prior results to
//! reuse. The EXECUTOR is an injected seam (`ProbeExecutor`): the
//! daemon (PR-4/M4) supplies the real transport — TCP/UDP connect by
//! default, ICMP only behind an explicit opt-in that requires
//! CAP_NET_RAW, which the core never assumes. No background scanning:
//! every probe run is caller-initiated. An unanswered probe is NEVER
//! proof an endpoint is offline — a timeout is simply the absence of
//! an observation (FR-19B); the planner keeps the prior value.
//!
//! Bounded three ways: a global per-run cap, a per-endpoint rate
//! limit (minimum age between probes of the SAME endpoint), and a
//! minimum reuse age (a fresh-enough observation is reused, not
//! re-probed). Cancellation is the caller's: the executor's
//! `cancelled` hook is polled between endpoints, so a stopped daemon
//! ends a run promptly without abandoning bookkeeping.

use std::collections::BTreeMap;
use std::time::Duration;

/// One prior or fresh probe observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// The measured round-trip time.
    pub rtt: Duration,
}

/// The planner's probe budget (FR-19B's bounded knobs; the defaults
/// follow the plan's U5 contract).
#[derive(Debug, Clone, Copy)]
pub struct ProbeBudget {
    /// Maximum endpoints probed in one run — the hard ceiling that
    /// keeps a run bounded regardless of shortlist size.
    pub max_probes_per_run: usize,
    /// Minimum age before a prior observation may be replaced (the
    /// per-endpoint rate limit).
    pub min_probe_interval: Duration,
    /// Observations younger than this are reused without probing.
    pub min_reuse_age: Duration,
}

impl Default for ProbeBudget {
    fn default() -> Self {
        Self {
            max_probes_per_run: 8,
            min_probe_interval: Duration::from_secs(60),
            min_reuse_age: Duration::from_secs(300),
        }
    }
}

/// The per-endpoint prior state the planner consults.
#[derive(Debug, Clone, Copy)]
pub struct EndpointState {
    /// The last observation, when one exists.
    pub observation: Option<Observation>,
    /// When the last PROBE attempt (answered or not) started, in
    /// milliseconds on the caller's clock.
    pub last_attempt_ms: u64,
}

/// The executor seam: the daemon's real transport (TCP/UDP by
/// default; ICMP only via its own CAP_NET_RAW-gated opt-in — never
/// assumed here). `cancelled` is polled between endpoints.
pub trait ProbeExecutor {
    /// Probes one endpoint, returning the RTT on answer. A timeout is
    /// `None` — never an offline verdict (FR-19B).
    fn probe(&mut self, endpoint: &str) -> Option<Duration>;
    /// Whether the run should stop before the next endpoint.
    fn cancelled(&mut self) -> bool {
        false
    }
}

/// One planner decision for an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeDecision {
    /// Probe now (the prior state is stale or absent).
    Probe,
    /// Reuse the prior observation (fresh enough).
    Reuse(Observation),
    /// Skip: the per-endpoint rate limit is not yet satisfied.
    RateLimited,
}

/// Plans one bounded run over the shortlist (in priority order — the
/// caller's ranked candidates). Pure: the same inputs plan the same
/// run.
///
/// The rules, per endpoint: with a prior observation, fresh-enough is
/// REUSED and stale is re-probed; with NO usable observation, an
/// attempt inside the per-endpoint rate-limit window is SKIPPED (the
/// hammering guard — unanswered endpoints are not re-attempted every
/// run); otherwise probe — until the global run cap is reached, after
/// which every remaining endpoint is skipped as `RateLimited` (the
/// budget arm; prior observations still serve selection).
#[must_use]
pub fn plan_run(
    shortlist: &[String],
    state: &BTreeMap<String, EndpointState>,
    budget: &ProbeBudget,
    now_ms: u64,
) -> BTreeMap<String, ProbeDecision> {
    let mut decisions = BTreeMap::new();
    let mut probes_budgeted = 0usize;
    for endpoint in shortlist {
        let decision = match state.get(endpoint) {
            Some(EndpointState {
                observation: Some(obs),
                last_attempt_ms,
            }) => {
                let age = Duration::from_millis(now_ms.saturating_sub(*last_attempt_ms));
                if age < budget.min_reuse_age {
                    ProbeDecision::Reuse(*obs)
                } else {
                    ProbeDecision::Probe
                }
            }
            // No usable observation: the rate limit is the hammering
            // guard for unanswered (or never-probed) endpoints.
            Some(EndpointState {
                observation: None,
                last_attempt_ms,
            }) => {
                let age = Duration::from_millis(now_ms.saturating_sub(*last_attempt_ms));
                if age < budget.min_probe_interval {
                    ProbeDecision::RateLimited
                } else {
                    ProbeDecision::Probe
                }
            }
            None => ProbeDecision::Probe,
        };
        let decision =
            if decision == ProbeDecision::Probe && probes_budgeted >= budget.max_probes_per_run {
                ProbeDecision::RateLimited
            } else {
                decision
            };
        if decision == ProbeDecision::Probe {
            probes_budgeted += 1;
        }
        decisions.insert(endpoint.clone(), decision);
    }
    decisions
}

/// Executes one planned run: probes every `Probe` endpoint through
/// the executor (polling `cancelled` between endpoints), returning
/// the merged observation table — reused priors plus fresh answers.
/// An unanswered probe contributes NOTHING for that endpoint (the
/// prior observation, when one exists, is what the caller keeps —
/// never an offline verdict).
pub fn run_planned(
    decisions: &BTreeMap<String, ProbeDecision>,
    state: &BTreeMap<String, EndpointState>,
    executor: &mut dyn ProbeExecutor,
) -> BTreeMap<String, Observation> {
    let mut table = BTreeMap::new();
    for (endpoint, decision) in decisions {
        match decision {
            ProbeDecision::Reuse(obs) => {
                table.insert(endpoint.clone(), *obs);
            }
            ProbeDecision::RateLimited => {
                if let Some(EndpointState {
                    observation: Some(obs),
                    ..
                }) = state.get(endpoint)
                {
                    table.insert(endpoint.clone(), *obs);
                }
            }
            ProbeDecision::Probe => {
                if executor.cancelled() {
                    break;
                }
                if let Some(rtt) = executor.probe(endpoint) {
                    table.insert(endpoint.clone(), Observation { rtt });
                }
            }
        }
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(
        id: &str,
        observation_ms: Option<u64>,
        last_attempt_ms: u64,
    ) -> (String, EndpointState) {
        (
            id.to_owned(),
            EndpointState {
                observation: observation_ms.map(|ms| Observation {
                    rtt: Duration::from_millis(ms),
                }),
                last_attempt_ms,
            },
        )
    }

    /// The FR-18 ceiling: a 20-endpoint shortlist under the default
    /// budget plans at most `max_probes_per_run` probes — the rest are
    /// budget-skipped, never planned.
    #[test]
    fn the_global_cap_bounds_the_run() {
        let shortlist: Vec<String> = (0..20).map(|i| format!("s{i}")).collect();
        let state = BTreeMap::new();
        let decisions = plan_run(&shortlist, &state, &ProbeBudget::default(), 1_000);
        let probes = decisions
            .values()
            .filter(|d| **d == ProbeDecision::Probe)
            .count();
        assert_eq!(
            probes,
            ProbeBudget::default().max_probes_per_run,
            "the run is bounded regardless of shortlist size"
        );
    }

    /// Fresh observations are REUSED, not re-probed (the reuse age).
    #[test]
    fn fresh_observations_are_reused() {
        let shortlist = vec!["a".to_owned()];
        let state: BTreeMap<_, _> = [endpoint("a", Some(42), 1_000)].into();
        let decisions = plan_run(&shortlist, &state, &ProbeBudget::default(), 1_500);
        assert_eq!(
            decisions["a"],
            ProbeDecision::Reuse(Observation {
                rtt: Duration::from_millis(42)
            })
        );
    }

    /// The hammering guard: an endpoint with NO observation whose
    /// last attempt is inside the probe interval is skipped —
    /// unanswered endpoints are not re-attempted every run.
    #[test]
    fn unanswered_endpoints_are_rate_limited() {
        let shortlist = vec!["a".to_owned()];
        // Attempted 30s ago (interval 60s), never answered.
        let state: BTreeMap<_, _> = [endpoint("a", None, 1_000)].into();
        let now = 1_000 + 30_000;
        let decisions = plan_run(&shortlist, &state, &ProbeBudget::default(), now);
        assert_eq!(decisions["a"], ProbeDecision::RateLimited);

        // Past the interval: probing again is allowed.
        let now = 1_000 + 90_000;
        let decisions = plan_run(&shortlist, &state, &ProbeBudget::default(), now);
        assert_eq!(decisions["a"], ProbeDecision::Probe);
    }

    /// Past every window: probe again.
    #[test]
    fn fully_stale_probes_again() {
        let shortlist = vec!["a".to_owned()];
        let state: BTreeMap<_, _> = [endpoint("a", Some(42), 1_000)].into();
        let now = 1_000 + 400_000;
        let decisions = plan_run(&shortlist, &state, &ProbeBudget::default(), now);
        assert_eq!(decisions["a"], ProbeDecision::Probe);
    }

    /// An unanswered probe is never an offline verdict: the run
    /// contributes nothing for that endpoint, and the PRIOR
    /// observation (held by the caller) still serves selection.
    #[test]
    fn an_unanswered_probe_contributes_nothing() {
        struct TimeoutAll;
        impl ProbeExecutor for TimeoutAll {
            fn probe(&mut self, _endpoint: &str) -> Option<Duration> {
                None
            }
        }
        let decisions: BTreeMap<_, _> = [("a".to_owned(), ProbeDecision::Probe)].into();
        let state = BTreeMap::new();
        let table = run_planned(&decisions, &state, &mut TimeoutAll);
        assert!(
            !table.contains_key("a"),
            "a timeout is the absence of an observation, never an offline verdict (FR-19B)"
        );
    }

    /// Cancellation stops the run between endpoints — the already-
    /// answered prefix survives, the rest is simply not probed.
    #[test]
    fn cancellation_stops_between_endpoints() {
        struct CancelAfterOne {
            answered: usize,
        }
        impl ProbeExecutor for CancelAfterOne {
            fn probe(&mut self, _endpoint: &str) -> Option<Duration> {
                self.answered += 1;
                Some(Duration::from_millis(10))
            }
            fn cancelled(&mut self) -> bool {
                self.answered >= 1
            }
        }
        let decisions: BTreeMap<_, _> = [
            ("a".to_owned(), ProbeDecision::Probe),
            ("b".to_owned(), ProbeDecision::Probe),
        ]
        .into();
        let state = BTreeMap::new();
        let table = run_planned(&decisions, &state, &mut CancelAfterOne { answered: 0 });
        assert_eq!(table.len(), 1, "the answered prefix survives");
        assert!(table.contains_key("a"));
    }
}
