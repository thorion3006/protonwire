//! The U6 selection engine (M3 PR-4): the daemon-side composition
//! every `select` request runs through (FR-23T end to end).
//!
//! What this module composes, in order:
//!
//! 1. **The cached catalog, strictly loaded** (S6/FR-23R): the S7
//!    scheduler is the only writer; selection READS the cache through
//!    the same strict walk and never fetches. No cached catalog is a
//!    typed refusal telling the caller to refresh — never a fabricated
//!    empty selection.
//! 2. **FR-23Q's physical-country sources**: explicit request →
//!    explicit config (`connection_groups.physical_country`) → the
//!    cached Muon user location (READ from the S10 cache; this module
//!    never performs a location fetch). A cache that fails its strict
//!    load is treated as ABSENT — for a country-excluding group that
//!    means the `physical-country-required` refusal, which is the
//!    fail-closed outcome (never a guess); the failure is warned.
//! 3. **The S8 entitlement + PF capability composition**
//!    (FR-23H/FR-87): the entitlement adapter arrives through a
//!    provider cell (the login family's idiom — the session lane
//!    installs it). An empty cell leaves the entitlement seam
//!    uncomposed, and a port-forwarding constraint then refuses with
//!    the core's typed composition error. Under an installed adapter
//!    the entitlement fact derives from the plan tier (paid ⇒
//!    entitled; the wire model carries no PF allowance field, so the
//!    composition rides the same recorded paid-plan classification the
//!    p2p/secure-core/tor allowances use), and the per-server
//!    CAPABILITY source composes as the EMPTY SET — no per-server PF
//!    source exists until M6's NAT-PMP lane supplies one, so a PF
//!    request under entitlement eliminates every candidate with the
//!    structured FR-22 report. Never fabricated. The SAME snapshot's
//!    recorded allowances (p2p/secure-core/tor = `Some(plan is
//!    paid)`) gate the REQUEST: a request naming a capability the
//!    plan lacks refuses typed before the core runs (the fourth
//!    member of the request-gate family — gateway, regional, PF;
//!    the tier stage stays the candidate filter).
//! 4. **The bounded on-demand prober** (U5's executor seam): for a
//!    latency-dependent ranking the engine derives the shortlist from
//!    the hard-filtered candidates in official order (Proton score,
//!    load, id — allowed signals only), plans one bounded run, and
//!    RESERVES every planned probe under the state lock BEFORE
//!    executing it (advancing `last_attempt_ms` — the hammering
//!    guard's contract, and the atomicity that keeps concurrent
//!    rounds from double-probing an endpoint); the write-back after
//!    the round records only observations. The whole round runs under
//!    a total wall-clock deadline (`round_deadline_ms`) beneath the
//!    10 s IPC request deadline. ICMP is honored as a config VALUE but
//!    its raw-socket executor is deliberately not wired: CAP_NET_RAW
//!    is never assumed, so the icmp arm observes nothing and a latency
//!    ranking over it fails closed (the typed data refusal), never a
//!    fabricated RTT.
//! 5. **The pure core** ([`protonwire_core::selection::select`] over
//!    the registry-resolved or direct request): the daemon maps the
//!    wire request onto the core vocabulary, supplies OS entropy for
//!    the random policy, and maps every typed refusal onto the RPC
//!    taxonomy — the FR-22 elimination report rides `details` on the
//!    no-eligible-server family so clients can render which constraint
//!    eliminated what.
//!
//! The FR-23E composition boundary: selection composes ONLY
//! selection-plane modifiers. The connection-plane family (`--netshield`,
//! `--nat`, `--lan-access`, the tunnel's protocol resolution, the
//! port-forwarding REQUEST) is the M4 tunnel's, and the
//! requested-versus-applied difference for it lands on the connection
//! transition — never from this query.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

use std::time::Duration;
use std::time::Instant;

use protonwire_api::entitlements::EntitlementsApi;

use protonwire_api::entitlements::EntitlementsError;
use protonwire_api::entitlements::PlanTier;
use protonwire_api::entitlements::VpnAccess;
use protonwire_api::entitlements::VpnEntitlements;
use protonwire_core::groups::GroupTarget;
use protonwire_core::groups::PhysicalCountrySources;
use protonwire_core::groups::PolicyProvenance;
use protonwire_core::groups::resolve_group;
use protonwire_core::probe::EndpointState;
use protonwire_core::probe::ProbeBudget;
use protonwire_core::probe::ProbeDecision;
use protonwire_core::probe::ProbeExecutor;
use protonwire_core::probe::plan_run;
use protonwire_core::probe::run_planned;
use protonwire_core::selection::Constraints;
use protonwire_core::selection::FeatureConstraint;
use protonwire_core::selection::ProtocolConstraint;
use protonwire_core::selection::RankingPolicy;
use protonwire_core::selection::SelectionContext;
use protonwire_core::selection::SelectionError;
use protonwire_core::selection::SelectionRequest;
use protonwire_core::selection::Target;
use protonwire_core::selection::WeightedSignals;
use protonwire_frontend_api::ConnectTarget;
use protonwire_frontend_api::GroupAvailability;
use protonwire_frontend_api::GroupDetails;
use protonwire_frontend_api::GroupProvenance;
use protonwire_frontend_api::GroupSummary;
use protonwire_frontend_api::GroupsCatalog;
use protonwire_frontend_api::HardFiltersReport;
use protonwire_frontend_api::PhysicalCountrySource;
use protonwire_frontend_api::PhysicalCountryValue;
use protonwire_frontend_api::ResolvedSelector;
use protonwire_frontend_api::RpcError;
use protonwire_frontend_api::RpcErrorCode;
use protonwire_frontend_api::SelectedServer;
use protonwire_frontend_api::SelectionCatalogProvenance;
use protonwire_frontend_api::SelectionFeature;
use protonwire_frontend_api::SelectionModifiers;
use protonwire_frontend_api::SelectionProtocol;
use protonwire_frontend_api::SelectionResult;
use protonwire_frontend_api::SpecialClass;
use protonwire_frontend_api::StageReport;
use protonwire_frontend_api::WeightedBreakdownWire;
use protonwire_frontend_api::WinnerSignals;
use protonwire_store::catalog::CachedCatalog;
use protonwire_store::catalog::CatalogCache;
use protonwire_store::catalog::CatalogCacheError;
use protonwire_store::catalog::CatalogDocument;
use protonwire_store::config::ProbeTransport;
use protonwire_store::config::SystemConfig;
use protonwire_store::location::CachedLocation;
use protonwire_store::location::LocationCache;
use protonwire_store::location::LocationCacheError;

/// The entitlement-adapter provider cell (the login family's twin of
/// `services::CatalogService`): the session lane INSTALLS the live
/// `&dyn EntitlementsApi` once the engine wiring lands. An empty cell
/// leaves the PF entitlement seam uncomposed — the pure core's typed
/// refusal, never a guessed entitlement.
///
/// The fetch is SINGLE-FLIGHT (Codex PR#9 round 4, P1): at most one
/// detached worker exists at a time — concurrent callers share that
/// worker's result channel, so repeated or concurrent requests cannot
/// accumulate unbounded threads and upstream calls.
#[derive(Default)]
pub struct EntitlementProvider {
    inner: RwLock<Option<Arc<dyn EntitlementsApi>>>,
    /// The in-flight fetch's broadcast slot (the single-flight seam):
    /// ONE worker, EVERY waiter observes the SAME outcome (Codex
    /// PR#9 round 5, P1 — mpsc is single-consumer; the first waiter
    /// consumed the only result and the rest read Disconnected).
    in_flight: Mutex<Option<EntitlementFetchSlot>>,
    /// The last successfully composed snapshot (the network-free
    /// listing's tier source — never initiating traffic).
    cached: Mutex<Option<VpnEntitlements>>,
}

/// The single-flight slot: the worker stores the result ONCE; every
/// waiter takes a clone of the SAME outcome (broadcast semantics over
/// a Mutex+Condvar pair). The error arm carries the structured
/// RpcError (Clone) so variants survive the broadcast.
type EntitlementFetchSlot = Arc<EntitlementFetchShared>;

struct EntitlementFetchShared {
    result: Mutex<Option<Result<VpnEntitlements, RpcError>>>,
    done: std::sync::Condvar,
}

impl EntitlementProvider {
    /// Installs (or replaces) the entitlements adapter.
    pub fn install(&self, api: Arc<dyn EntitlementsApi>) {
        *self.inner.write().expect("entitlement provider lock") = Some(api);
    }

    /// The current adapter, if the session lane has installed one.
    pub fn current(&self) -> Option<Arc<dyn EntitlementsApi>> {
        self.inner
            .read()
            .expect("entitlement provider lock")
            .clone()
    }

    /// SINGLE-FLIGHT bounded fetch (Codex PR#9 rounds 4+5, P1): the
    /// first caller spawns ONE detached worker and parks the BROADCAST
    /// slot; concurrent callers take a clone of that slot and every
    /// waiter observes the SAME outcome — the worker stores the
    /// result once and signals the condvar; each waiter clones it.
    /// At most one worker (and one upstream fetch) exists per instant.
    fn single_flight_slot(&self) -> Result<EntitlementFetchSlot, RpcError> {
        let mut slot = self.in_flight.lock().expect("in-flight slot lock");
        if let Some(existing) = slot.as_ref() {
            return Ok(Arc::clone(existing));
        }
        let Some(adapter) = self.current() else {
            return Err(RpcError::new(
                RpcErrorCode::Internal,
                "single-flight slot requested with no adapter installed",
            ));
        };
        let shared: EntitlementFetchSlot = Arc::new(EntitlementFetchShared {
            result: Mutex::new(None),
            done: std::sync::Condvar::new(),
        });
        let worker_shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            // The structured error mapping happens ONCE in the worker
            // (Codex PR#9 round 6, P2): RpcError is Clone, so every
            // waiter receives the VARIANT-preserving outcome — Transport
            // → NetworkUnavailable, Api/Malformed → Internal — never the
            // everything-is-a-network-outage flattening the String arm
            // caused.
            let outcome = adapter.fetch().map_err(|error| match error {
                EntitlementsError::Transport(detail) => RpcError::new(
                    RpcErrorCode::NetworkUnavailable,
                    format!("entitlements read failed: {detail}"),
                ),
                other => RpcError::new(
                    RpcErrorCode::Internal,
                    format!("entitlements read failed: {other}"),
                ),
            });
            let mut result = worker_shared.result.lock().expect("fetch result lock");
            *result = Some(outcome);
            worker_shared.done.notify_all();
        });
        *slot = Some(Arc::clone(&shared));
        Ok(shared)
    }

    /// Waits on the broadcast slot for the outcome, budget-bounded:
    /// `Ok(Some(outcome))` when the worker finished inside the
    /// budget (the SAME clone for every waiter — broadcast);
    /// `Ok(None)` on the budget timeout (the worker may still land
    /// for the next waiter).
    fn wait_for_outcome(
        &self,
        slot: &EntitlementFetchSlot,
        budget: Duration,
    ) -> Option<Result<VpnEntitlements, RpcError>> {
        let guard = slot.result.lock().expect("fetch result lock");
        if guard.is_some() {
            return guard.deref().clone();
        }
        let (result, _timeout) = slot
            .done
            .wait_timeout_while(guard, budget, |r| r.is_none())
            .expect("fetch condvar");
        result.deref().clone()
    }

    /// Clears the single-flight slot when no waiter still holds it is
    /// determinable cheaply — the next request starts a fresh worker
    /// once the slot is cleared by the LAST waiter to observe the
    /// outcome (the caller clears after consuming; a racing earlier
    /// timeout leaves the slot for the landed result to be observed).
    fn clear_single_flight(&self, consumed: &EntitlementFetchSlot) {
        // Clear ONLY the slot whose outcome this waiter consumed
        // (Codex PR#9 round 6, P1): an unconditional take() let an old
        // waiter remove a NEW slot another request had installed after
        // the first clear — a third worker could then spawn while the
        // second still fetched, defeating the one-worker bound.
        let mut slot = self.in_flight.lock().expect("in-flight slot lock");
        if let Some(current) = slot.as_ref()
            && Arc::ptr_eq(current, consumed)
        {
            *slot = None;
        }
    }

    /// The last successfully composed snapshot (the network-free
    /// surfaces' tier source — Codex PR#9 round 4, P2). None until
    /// the first successful composition.
    fn cached_snapshot(&self) -> Option<VpnEntitlements> {
        self.cached.lock().expect("entitlement cache lock").clone()
    }

    /// Stores a successfully composed snapshot for the network-free
    /// surfaces.
    fn store_snapshot(&self, snapshot: VpnEntitlements) {
        *self.cached.lock().expect("entitlement cache lock") = Some(snapshot);
    }
}

/// The in-memory probe table (U5's state): one [`EndpointState`] per
/// logical id, keyed by the LOGICAL id (the same key the latency table
/// and the shortlist use — the executor resolves the id to a network
/// endpoint fresh from the loaded catalog each run, so no stale
/// address mapping is ever cached or logged).
///
/// In-memory by design for M3: the reuse windows are seconds-to-minutes
/// and a restart re-probes under the same global bounds — persistence
/// would outlive the addresses' meaning for no selection value.
#[derive(Default)]
struct ProbeTable {
    state: Mutex<BTreeMap<String, EndpointState>>,
}

/// The production wall clock in milliseconds (Unix epoch).
fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// The production TCP connect: the unprivileged latency measurement
/// (connect RTT). A failure — timeout, refused, unreachable — is `None`
/// (the absence of an observation, never an offline verdict).
fn tcp_connect(addr: SocketAddr, timeout: Duration) -> Option<Duration> {
    let start = Instant::now();
    TcpStream::connect_timeout(&addr, timeout)
        .ok()
        .map(|_| start.elapsed())
}

/// The selection engine: everything a `select` request composes, over
/// the daemon's own services. Constructed strictly at startup beside
/// the scheduler; every request path through it is read-only against
/// the daemon's persisted state (the probe table's mutex is the only
/// mutation, and it is bounded by the U5 planner).
pub struct SelectionEngine {
    config: Arc<SystemConfig>,
    /// The S8 entitlement adapter cell (PF composition).
    entitlement: EntitlementProvider,
    /// The bounded on-demand prober's state.
    probes: ProbeTable,
    /// The clock the planner and the write-back share — injectable so
    /// the rate-limit windows are testable.
    now_ms: Box<dyn Fn() -> u64 + Send + Sync>,
    /// The transport seam — the TCP connect above in production,
    /// injected in tests (the never-answers / always-answers arms).
    connect: Box<dyn Fn(SocketAddr, Duration) -> Option<Duration> + Send + Sync>,
    /// The strict catalog read (the F1 chown-seam precedent: the
    /// PRODUCTION closure runs the fs_trust walk, which only a root
    /// daemon's root-owned tree can pass; tests inject the planted
    /// document past the walk — the walk itself is pinned by the store
    /// suite and the S9 startup tests, the COMPOSITION is what these
    /// walls pin).
    catalog_read: Box<dyn Fn() -> Result<Option<CachedCatalog>, CatalogCacheError> + Send + Sync>,
    /// The strict location read (same seam shape, same rationale).
    location_read:
        Box<dyn Fn() -> Result<Option<CachedLocation>, LocationCacheError> + Send + Sync>,
}

impl SelectionEngine {
    /// The production engine over the daemon's cache location and
    /// trust root.
    pub fn new(config: Arc<SystemConfig>, cache_dir: &Path, trust_root: &Path) -> Self {
        let cache_file = cache_dir.join("servers.json");
        let location_file = cache_dir.join("location.json");
        let trust_root = trust_root.to_path_buf();
        let catalog_trust_root = trust_root.clone();
        Self {
            config,
            entitlement: EntitlementProvider::default(),
            probes: ProbeTable::default(),
            now_ms: Box::new(system_now_ms),
            connect: Box::new(tcp_connect),
            catalog_read: Box::new(move || {
                CatalogCache::new(&cache_file).load_strict(&catalog_trust_root)
            }),
            location_read: Box::new(move || {
                LocationCache::new(&location_file).load_strict(&trust_root)
            }),
        }
    }

    /// The entitlement adapter cell (the session lane's install seam).
    pub fn entitlement(&self) -> &EntitlementProvider {
        &self.entitlement
    }

    /// The probe table's current state — the test surface for the
    /// write-back contract (production callers never read it whole).
    #[cfg(test)]
    fn probe_state(&self) -> BTreeMap<String, EndpointState> {
        self.probes.state.lock().expect("probe table lock").clone()
    }

    /// The strict catalog read every selection runs against (FR-23R:
    /// a read of the daemon's cache, never a fetch). `Ok(None)` is
    /// the legitimate nothing-cached-yet state.
    fn cached_catalog(&self) -> Result<Option<(Option<String>, u64, CatalogDocument)>, RpcError> {
        match (self.catalog_read)() {
            Ok(Some(cached)) => {
                let document =
                    CatalogDocument::from_bytes(cached.body.as_bytes()).map_err(|error| {
                        RpcError::new(
                            RpcErrorCode::Internal,
                            format!(
                                "the cached catalog body no longer parses against the live \
                                 model: {error}"
                            ),
                        )
                    })?;
                Ok(Some((cached.etag, cached.fetched_unix, document)))
            }
            Ok(None) => Ok(None),
            Err(error) => Err(RpcError::new(
                RpcErrorCode::ConfigInvalid,
                format!("cached catalog failed the strict load: {error}"),
            )),
        }
    }

    /// The configured `balanced` weights (P2-2's composition: the user
    /// config is what a v1 balanced policy runs under — catalog-declared
    /// and request-explicit weights do not exist yet; the precedence is
    /// recorded on the core's `to_selection_policy`). The config schema
    /// has no `history` field, so that term composes as FR-16's
    /// documented 0.00 default.
    fn balanced_weights(&self) -> WeightedSignals {
        let weights = &self.config.server_selection.balanced_weights;
        WeightedSignals {
            load: weights.load,
            latency: weights.latency,
            stability: weights.stability,
            feature_match: weights.feature_match,
            history: 0.0,
        }
    }

    /// The probe budget from the config's latency-probe policy. The
    /// per-endpoint rate interval (the hammering guard) has no config
    /// knob: 60s is the U5 contract's floor, and a config value below
    /// it would re-arm exactly the hammering FR-19B forbids.
    fn probe_budget(&self) -> ProbeBudget {
        let probe = &self.config.server_selection.latency_probe;
        ProbeBudget {
            max_probes_per_run: probe.max_candidates as usize,
            min_probe_interval: Duration::from_secs(60),
            min_reuse_age: Duration::from_secs(u64::from(probe.result_min_age_minutes) * 60),
        }
    }

    /// Reads the cached Muon location's country (FR-23Q's third
    /// source). A strict-load failure is treated as ABSENT with a
    /// warning: for a country-excluding group the downstream refusal
    /// (`physical-country-required`) is the fail-closed outcome — the
    /// alternative (failing every select over an unrelated cache)
    /// would couple the two documents' availability for no security
    /// gain, since absence already refuses the country-dependent path.
    fn cached_location_country(&self) -> Option<String> {
        match (self.location_read)() {
            Ok(Some(location)) => Some(location.country),
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "user-location cache failed its strict load; treating it as absent \
                     (country-dependent groups refuse physical-country-required)"
                );
                None
            }
        }
    }

    /// Composes FR-23Q's sources and reports which one won.
    fn physical_country(&self, explicit_request: Option<&str>) -> Option<PhysicalCountryValue> {
        if let Some(country) = explicit_request {
            return Some(PhysicalCountryValue {
                country: country.to_owned(),
                source: PhysicalCountrySource::ExplicitRequest,
            });
        }
        if let Some(country) = self.config.connection_groups.physical_country.as_deref() {
            return Some(PhysicalCountryValue {
                country: country.to_owned(),
                source: PhysicalCountrySource::Config,
            });
        }
        self.cached_location_country()
            .map(|country| PhysicalCountryValue {
                country,
                source: PhysicalCountrySource::CachedLocation,
            })
    }

    /// Composes the S8 entitlement snapshot once per request
    /// (FR-23H/87 for the PF fact, FR-23P's account-entitlement stage
    /// for the tier). `Ok(None)` = the cell is empty (no adapter
    /// installed — the session lane's M4 wiring): every seam the
    /// snapshot feeds then composes as uncomposed (the PF constraint
    /// refuses typed; the tier stage eliminates nothing). The wait
    /// clamps to `request_deadline`'s REMAINDER (round 7): the
    /// configured budget only tightens it, never extends the wait
    /// past the deadline `resolve()` arms.
    fn entitlement_composition(
        &self,
        request_deadline: Instant,
    ) -> Result<Option<VpnEntitlements>, RpcError> {
        if self.entitlement.current().is_none() {
            // No adapter installed = the login-free surface: no
            // session exists, no account, no tier — None is the
            // documented semantics (queryable without guessing).
            return Ok(None);
        }
        // SINGLE-FLIGHT (Codex PR#9 round 4, P1): concurrent callers
        // share one worker's channel — no thread-per-request
        // accumulation. RPC-DEADLINE-BOUNDED (round 3, P1): a budget
        // miss is FAIL-CLOSED. An unusable snapshot (round 4, P1:
        // NoAccess/Waitlisted, or an absent MaxTier) is likewise a
        // typed refusal — never a tier-less selection.
        let configured = std::time::Duration::from_millis(
            self.config.server_selection.entitlement_fetch_budget_ms,
        );
        // DEADLINE CLAMP (Codex PR#9 round 7, P2): validation permits
        // a 9.5 s budget while `resolve()` arms ONE 9 s request
        // deadline spanning this composition and the probe round —
        // min() keeps whichever bound EXPIRES FIRST, so a slow fetch
        // gives up at the deadline's remainder (fail-closed), never
        // overruns it toward the IPC client's 10 s timeout.
        let budget = configured.min(request_deadline.saturating_duration_since(Instant::now()));
        let slot = self.entitlement.single_flight_slot()?;
        let outcome = self.entitlement.wait_for_outcome(&slot, budget);
        // The slot clears only when the outcome LANDED for this waiter
        // AND the cell still holds THIS slot (a racing waiter's clear +
        // a new install must survive); a budget-timeout waiter leaves
        // it (the landed result serves the next waiter — broadcast).
        if outcome.is_some() {
            self.entitlement.clear_single_flight(&slot);
        }
        let Some(result) = outcome else {
            tracing::warn!(
                budget_ms = budget.as_millis() as u64,
                "entitlement composition exceeded its deadline-clamped wait; refusing \
                 (fail-closed: an installed adapter's tier must never be guessed)"
            );
            return Err(RpcError::new(
                RpcErrorCode::EntitlementMissing,
                format!(
                    "the entitlement read exceeded its {} ms wait (deadline-clamped) — the \
                     account tier cannot be composed safely; retry shortly",
                    budget.as_millis()
                ),
            ));
        };
        match result {
            Ok(entitlements) => {
                if entitlements.vpn_access != VpnAccess::Active {
                    return Err(RpcError::new(
                        RpcErrorCode::EntitlementMissing,
                        format!(
                            "the account's VPN access is {:?} — no server may be selected",
                            entitlements.vpn_access
                        ),
                    ));
                }
                if entitlements.max_tier.is_none() {
                    return Err(RpcError::new(
                        RpcErrorCode::EntitlementMissing,
                        "the entitlement snapshot carries no MaxTier — the account tier \
                         cannot be composed safely; retry after the next refresh",
                    ));
                }
                self.entitlement.store_snapshot(entitlements.clone());
                Ok(Some(entitlements))
            }
            // The worker pre-mapped the variant (Transport →
            // NetworkUnavailable; Api/Malformed → Internal); the
            // clone preserves it.
            Err(rpc) => Err(rpc),
        }
    }

    /// The account-entitlement tier over the S8 wire `MaxTier` (0
    /// free / 1 basic / 2 plus / 3 PM), saturated into the catalog's
    /// `i8` tier domain — the core's account-entitlement stage
    /// eliminates every candidate above it (FR-23P). An absent
    /// `MaxTier` is not a tier (the S8 tri-state rule): `None`.
    fn account_tier(
        entitlements: Option<&protonwire_api::entitlements::VpnEntitlements>,
    ) -> Option<i8> {
        entitlements
            .and_then(|snapshot| snapshot.max_tier)
            .map(|tier| tier.min(i64::from(i8::MAX)) as i8)
    }

    /// The plan-feature capability a request names but the plan
    /// lacks (Codex PR#9 round 8, P1): the recorded allowances
    /// (`FeatureAllowances`: p2p/secure-core/tor = `Some(plan is
    /// paid)` — the parity vocabulary `servers.p2p|tor|secure-core:
    /// entitlement: paid`) gate the REQUEST the way the gateway
    /// business gate and the paid-location gate gate theirs — the
    /// per-server tier stage stays the CANDIDATE filter (the
    /// entitlements model's recorded boundary); this is the
    /// request-level refusal FR-23S's "precise entitlement error"
    /// names. `None` (no snapshot) refuses fail-closed — the family
    /// semantics (gateway, regional, PF). BOTH arms name the
    /// capability (the PF precedent: an optional request still
    /// weights ranking toward it). Returns the capability token and
    /// its allowance; `None` = every named capability is allowed.
    fn unmet_capability(
        entitlements: Option<&VpnEntitlements>,
        request: &SelectionRequest,
    ) -> Option<(&'static str, Option<bool>)> {
        let allowances = entitlements.map(|snapshot| &snapshot.features);
        let constraints = &request.constraints;
        [
            (
                matches!(request.target, Target::SecureCore { .. })
                    || constraints
                        .required_features
                        .contains(&FeatureConstraint::SecureCore)
                    || constraints
                        .optional_features
                        .contains(&FeatureConstraint::SecureCore),
                "secure-core",
                allowances.and_then(|features| features.secure_core),
            ),
            (
                constraints
                    .required_features
                    .contains(&FeatureConstraint::P2p)
                    || constraints
                        .optional_features
                        .contains(&FeatureConstraint::P2p),
                "p2p",
                allowances.and_then(|features| features.p2p),
            ),
            (
                constraints
                    .required_features
                    .contains(&FeatureConstraint::Tor)
                    || constraints
                        .optional_features
                        .contains(&FeatureConstraint::Tor),
                "tor",
                allowances.and_then(|features| features.tor),
            ),
        ]
        .into_iter()
        .find_map(|(named, capability, allowance)| {
            (named && allowance != Some(true)).then_some((capability, allowance))
        })
    }

    /// The CACHED entitlement tier for network-free surfaces (the
    /// built-in listing, Codex PR#9 round 4, P2): reads the last
    /// successfully composed snapshot without initiating any traffic.
    /// None when no snapshot exists — the listing reports the honest
    /// unknown, never a guessed tier, never a blocked RPC.
    fn cached_entitlement_tier(&self) -> Option<i8> {
        self.entitlement
            .cached_snapshot()
            .as_ref()
            .and_then(|snapshot| snapshot.max_tier)
            .map(|tier| tier.min(i64::from(i8::MAX)) as i8)
    }

    /// The PF entitlement fact off the same snapshot: the wire model
    /// carries no PF allowance field, so the composition rides the
    /// recorded paid-plan classification (the same rule the
    /// p2p/secure-core/tor allowances derive from — the S8 module
    /// docs). With the capability set empty today, this fact only
    /// differentiates the refusal's code, never a pass.
    fn pf_entitlement(
        entitlements: Option<&protonwire_api::entitlements::VpnEntitlements>,
    ) -> Option<bool> {
        entitlements.map(|snapshot| snapshot.plan_tier == Some(PlanTier::Paid))
    }

    /// The empty per-server PF capability composition (FR-87's honest
    /// TODAY): no per-server source exists until M6's NAT-PMP lane
    /// supplies one.
    fn port_forwarding_capable(&self) -> BTreeSet<String> {
        BTreeSet::new()
    }

    /// OS entropy for the random policy (the pure core fabricates no
    /// randomness; the daemon supplies it — m2-plan decision 3).
    fn os_entropy() -> Result<u64, RpcError> {
        let mut bytes = [0u8; 8];
        // The scheduler's posture: getrandom cannot fail on supported
        // platforms; a failure means a broken CSPRNG and the random
        // policy refuses rather than drawing pseudo-randomness.
        getrandom::getrandom(&mut bytes).map_err(|_| {
            RpcError::new(
                RpcErrorCode::Internal,
                "the OS CSPRNG refused the random policy's entropy draw",
            )
        })?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Runs one bounded probe round over `shortlist` (logical ids in
    /// priority order) and returns the merged observation table.
    ///
    /// The RESERVATION protocol (the Codex PR-9 P1): the plan AND the
    /// attempt-clock advance for every endpoint the plan will probe
    /// happen under ONE lock hold, BEFORE execution — a concurrent
    /// round's plan then sees those endpoints rate-limited, so no
    /// endpoint is probed twice inside the per-endpoint interval and
    /// the global per-run bound holds across sessions. (Pre-fix the
    /// table was cloned and unlocked before planning, with the clock
    /// advancing only at the write-back — exactly the window two
    /// concurrent rounds both slipped through.)
    ///
    /// The write-back after the round records ONLY observations (and
    /// their answer times); the attempt clock already moved at the
    /// reservation, which is also what an unanswered probed endpoint
    /// keeps — the hammering guard's contract.
    ///
    /// The WHOLE round is bounded by the configured total deadline
    /// (the Codex PR-9 arithmetic: a serial worst case of
    /// 20 × 750 ms ≈ 15 s must never answer `--by latency` with the
    /// 10 s RPC transport timeout): probing stops at the deadline, the
    /// answered prefix survives, and the unprobed fall to the FR-18
    /// shortlist boundary.
    fn probe_round(
        &self,
        catalog: &CatalogDocument,
        shortlist: Vec<String>,
        request_deadline: Instant,
    ) -> BTreeMap<String, Duration> {
        let probe_config = &self.config.server_selection.latency_probe;
        if !probe_config.enabled || shortlist.is_empty() {
            return BTreeMap::new();
        }
        // The round deadline clamps to the REQUEST deadline's remainder
        // (Codex PR#9 round 3, P1): 6 s of entitlement composition plus
        // an unclamped 8 s round would exceed the 10 s IPC bar; the
        // round gets whatever the single request deadline leaves.
        let configured =
            Instant::now() + Duration::from_millis(u64::from(probe_config.round_deadline_ms));
        let round_deadline = configured.min(request_deadline);
        let now = (self.now_ms)();
        let budget = self.probe_budget();

        // Plan + reserve atomically. `state` is the same locked-now
        // snapshot the plan ran over (its observations feed
        // `run_planned`'s rate-limited passthrough; the reservation
        // only advances attempt clocks, which that path never reads).
        let (state, decisions) = {
            let mut guard = self.probes.state.lock().expect("probe table lock");
            let state = guard.clone();
            let decisions = plan_run(&shortlist, &state, &budget, now);
            for endpoint in &shortlist {
                if decisions.get(endpoint) == Some(&ProbeDecision::Probe) {
                    guard.entry(endpoint.clone()).or_default().last_attempt_ms = now;
                }
            }
            (state, decisions)
        };

        // Resolve the endpoints fresh from the loaded catalog (never a
        // cached id→address mapping, never logged — the PR-3 review's
        // sec track item).
        let timeout = Duration::from_millis(u64::from(probe_config.timeout_ms));
        let endpoints: BTreeMap<String, SocketAddr> = shortlist
            .iter()
            .filter_map(|id| Some((id.clone(), probe_endpoint(catalog, id)?)))
            .collect();
        let connect = &self.connect;
        let transport = probe_config.transport;
        let mut executor = TransportExecutor {
            transport,
            timeout,
            endpoints,
            connect,
            round_deadline,
        };
        let run = run_planned(&shortlist, &decisions, &state, &mut executor);
        let observed = run.observations;

        // The write-back: observations only, plus the reservation
        // RELEASE for planned-but-never-attempted endpoints (Codex
        // PR#9, P2: a deadline cut before an endpoint's turn must not
        // rate-limit it for the 60 s interval — the untouched endpoint
        // returns to probeable immediately; an attempted one keeps its
        // reservation, the hammering guard's contract).
        let answered_at = (self.now_ms)();
        let attempted: std::collections::BTreeSet<&str> =
            run.attempted.iter().map(String::as_str).collect();
        let mut guard = self.probes.state.lock().expect("probe table lock");
        for endpoint in &shortlist {
            if decisions.get(endpoint) != Some(&ProbeDecision::Probe) {
                continue;
            }
            if !attempted.contains(endpoint.as_str()) {
                // Never attempted: release the reservation — restore
                // the prior clock (0 when the reservation created the
                // entry; the pre-round value otherwise — the snapshot
                // in `state` holds it).
                match state.get(endpoint) {
                    Some(prior) => {
                        if let Some(entry) = guard.get_mut(endpoint) {
                            entry.last_attempt_ms = prior.last_attempt_ms;
                        }
                    }
                    None => {
                        guard.remove(endpoint);
                    }
                }
                continue;
            }
            if let Some(observation) = observed.get(endpoint) {
                let entry = guard.entry(endpoint.clone()).or_default();
                entry.observation = Some(*observation);
                entry.observed_at_ms = answered_at;
            }
        }
        // The latency table the ranking consumes: the run's merged
        // observations (reused priors plus fresh answers) keyed by
        // logical id, RTT-only.
        observed
            .into_iter()
            .map(|(id, observation)| (id, observation.rtt))
            .collect()
    }

    /// Derives the probe shortlist: the hard-filtered candidates in
    /// official order (Proton score ascending, load, id — allowed
    /// signals only, FR-19), capped at the config's candidate count.
    /// The FILTER stages are policy-independent, so this runs over the
    /// resolved request before any ranking.
    fn probe_shortlist(
        &self,
        catalog: &CatalogDocument,
        request: &SelectionRequest,
        context: &SelectionContext,
    ) -> Vec<String> {
        let filtered = protonwire_core::selection::filter_candidates(
            catalog,
            &SelectionRequest {
                policy: RankingPolicy::Official,
                ..request.clone()
            },
            context,
        );
        let Ok((survivors, _)) = filtered else {
            return Vec::new();
        };
        let cap = self.config.server_selection.latency_probe.max_candidates as usize;
        let mut ordered: Vec<&protonwire_store::catalog::LogicalServer> = survivors;
        ordered.sort_by(|a, b| {
            a.score
                .unwrap_or(f32::MAX)
                .total_cmp(&b.score.unwrap_or(f32::MAX))
                .then_with(|| a.load.unwrap_or(i8::MAX).cmp(&b.load.unwrap_or(i8::MAX)))
                .then_with(|| a.id.cmp(&b.id))
        });
        ordered
            .into_iter()
            .take(cap)
            .map(|s| s.id.clone())
            .collect()
    }

    /// The single request deadline spanning the entitlement
    /// composition and the probe round (Codex PR#9 round 3, P1): the
    /// IPC client's default request timeout is 10 s
    /// (`ipc::client::DEFAULT_REQUEST_TIMEOUT`); this leaves 1 s of
    /// headroom for the selection itself and the reply write.
    fn request_deadline_ms(&self) -> u64 {
        9_000
    }

    /// Resolves a selection request end to end (the `Select` handler's
    /// body). Read-only against daemon state except the bounded probe
    /// round a latency-dependent ranking triggers.
    pub fn resolve(
        &self,
        target: &ConnectTarget,
        modifiers: &SelectionModifiers,
    ) -> Result<Box<SelectionResult>, RpcError> {
        // ONE request deadline spans the entitlement composition AND
        // the probe round (Codex PR#9 round 3, P1): independent serial
        // budgets (6 s + 8 s defaults) exceeded the 10 s IPC request
        // timeout. The probe round clamps its own configured deadline
        // to whatever this deadline leaves.
        let request_deadline = Instant::now() + Duration::from_millis(self.request_deadline_ms());
        let Some((etag, fetched_unix, catalog)) = self.cached_catalog()? else {
            return Err(RpcError::new(
                RpcErrorCode::NoEligibleServer,
                "no server catalog is cached yet — run `protonwire servers refresh` first \
                 (selection reads the cache; it never fetches)",
            ));
        };

        let (required_features, optional_features) =
            wire_features(&modifiers.required_features, &modifiers.optional_features);
        let required_protocol = wire_protocol(modifiers.required_protocol);

        // The S8 entitlement snapshot, composed ONCE: the PF fact
        // (None = uncomposed — the core refuses) and the
        // account-entitlement tier (None = the stage eliminates
        // nothing; FR-23P's own stage ahead of online state). The
        // wait clamps to this request deadline's remainder (round 7)
        // — the configured budget only tightens it.
        let entitlements = self.entitlement_composition(request_deadline)?;
        let pf_entitled = Self::pf_entitlement(entitlements.as_ref());
        let account_tier = Self::account_tier(entitlements.as_ref());
        // The GATEWAY authorization (Codex PR#9 rounds 4+5, P1): a
        // gateway target requires the business/organization
        // entitlement — AND an exact SERVER target that names a
        // gateway LOGICAL requires it identically (the round-4 gate
        // matched only the Gateway wire variant, so `select server
        // <gateway-logical>` bypassed it; the core's exact-Server arm
        // has no fleet-type restriction). None (login-free) and
        // Some(false) both refuse; only an affirmative proceeds.
        let is_business = entitlements
            .as_ref()
            .and_then(|snapshot| snapshot.is_business)
            .unwrap_or(false);
        let target_names_gateway = match target {
            ConnectTarget::Gateway { .. } => true,
            ConnectTarget::Server { server } => catalog
                .logical_servers
                .iter()
                .any(|logical| logical.name == *server && logical.is_gateway()),
            _ => false,
        };
        if target_names_gateway && !is_business {
            return Err(RpcError::new(
                RpcErrorCode::EntitlementMissing,
                "gateway targets require a Proton Business (organization) entitlement — \
                 this account is not entitled to dedicated servers",
            ));
        }
        let pf_requested = modifiers
            .required_features
            .contains(&SelectionFeature::PortForwarding)
            || modifiers
                .optional_features
                .contains(&SelectionFeature::PortForwarding);

        // The group arm resolves through the registry (FR-23P's
        // override discipline, FR-23Q's sources, P2-2's weights); the
        // direct arm maps the grammar onto the core vocabulary.
        let (request, group) = match target {
            ConnectTarget::Group { group_id } => {
                let cached_country = self.cached_location_country();
                let sources = PhysicalCountrySources {
                    explicit_request: modifiers.physical_country.as_deref(),
                    config: self.config.connection_groups.physical_country.as_deref(),
                    cached_location: cached_country.as_deref(),
                };
                let resolved = resolve_group(
                    group_id,
                    modifiers.by.as_deref(),
                    &sources,
                    &self.balanced_weights(),
                )
                .map_err(group_error_to_rpc)?;
                // The PAID-LOCATION gate (Codex PR#9 round 5, P1): the
                // registry classifies every protonwire:fastest-*
                // regional group as PaidLocationSelection — choosing a
                // location IS the paid capability, so a non-paid plan
                // refuses outright rather than relying on the per-server
                // tier filter (a region containing a tier-0 server
                // would otherwise select under a free account).
                if resolved.group.entitlement
                    == protonwire_core::groups::GroupEntitlement::PaidLocationSelection
                    && entitlements
                        .as_ref()
                        .and_then(|snapshot| snapshot.plan_tier)
                        != Some(PlanTier::Paid)
                {
                    return Err(RpcError::new(
                        RpcErrorCode::EntitlementMissing,
                        "regional location selection requires a paid plan — this account's \
                         plan does not include choosing a location",
                    ));
                }
                let provenance = GroupProvenance {
                    group_id: group_id.clone(),
                    origin: resolved.group.origin.as_str().to_owned(),
                    policy_provenance: match resolved.policy_provenance {
                        PolicyProvenance::CatalogDefault => "catalog-default",
                        PolicyProvenance::DeclaredOverride => "declared-override",
                    }
                    .to_owned(),
                };
                let request = merge_group_modifiers(
                    group_id,
                    resolved.request,
                    modifiers,
                    required_features,
                    optional_features,
                    required_protocol,
                )?;
                (request, Some(provenance))
            }
            direct => (
                direct_request(
                    direct,
                    modifiers,
                    required_features,
                    optional_features,
                    required_protocol,
                    &self.balanced_weights(),
                )?,
                None,
            ),
        };

        // The plan-feature capability gate (Codex PR#9 round 8, P1):
        // the fourth member of the request-gate family (the gateway
        // business gate, the paid-location gate, the PF composition) —
        // a request naming p2p/tor/secure-core under a plan without
        // the capability refuses typed BEFORE the core runs (the tier
        // stage stays the candidate filter; the pre-fix gap handed a
        // free account a tier-0 P2P selection).
        if let Some((capability, _)) = Self::unmet_capability(entitlements.as_ref(), &request) {
            return Err(RpcError::new(
                RpcErrorCode::EntitlementMissing,
                format!(
                    "{capability} selection requires a paid plan — this account's plan does \
                     not include the {capability} capability"
                ),
            ));
        }

        // FR-23T's "when relevant": the physical country reports when
        // the group's semantics used it, or when the caller named it
        // explicitly (a named value is provenance the caller asked to
        // see even where no stage consumes it).
        let used_physical_country = request.constraints.exclude_physical_country;
        let physical_country = if used_physical_country || modifiers.physical_country.is_some() {
            self.physical_country(modifiers.physical_country.as_deref())
        } else {
            None
        };

        let mut context = SelectionContext {
            account_tier,
            port_forwarding_entitled: pf_entitled,
            port_forwarding_capable: pf_entitled.map(|_| self.port_forwarding_capable()),
            ..SelectionContext::default()
        };

        // A latency-dependent ranking probes first (FR-18): the
        // shortlist is hard-filter + official order, the run is bounded
        // by the U5 planner, and the merged table (reused priors plus
        // fresh answers) is what the ranking consumes.
        let latency_weighted = match &request.policy {
            RankingPolicy::Latency => true,
            RankingPolicy::Balanced { weights } => weights.latency > 0.0,
            _ => false,
        };
        if latency_weighted {
            let shortlist = self.probe_shortlist(&catalog, &request, &context);
            context.latency = self.probe_round(&catalog, shortlist, request_deadline);
        }

        // The random policy draws on OS entropy.
        if matches!(request.policy, RankingPolicy::Random) {
            context.random_entropy = Some(Self::os_entropy()?);
        }

        let outcome = protonwire_core::selection::select(&catalog, &request, &context)
            .map_err(|error| selection_error_to_rpc_pf_explained(error, pf_requested))?;
        let winner = outcome
            .ranked
            .first()
            .ok_or_else(|| RpcError::new(RpcErrorCode::Internal, "selection returned no winner"))?;

        let selector = match &group {
            Some(provenance) => ResolvedSelector {
                target: "group".into(),
                detail: Some(provenance.group_id.clone()),
                policy: policy_token(&request.policy),
            },
            None => direct_selector(target, &request.policy),
        };

        let signals = &winner.signals;
        let provenance = if signals.weighted.is_some() {
            "weighted-breakdown"
        } else if signals.latency.is_some() {
            "probe-observed"
        } else {
            "catalog-only"
        };
        let requested_features = modifiers
            .required_features
            .iter()
            .chain(modifiers.optional_features.iter())
            .map(|feature| feature.as_str().to_owned())
            .collect::<Vec<_>>();

        Ok(Box::new(SelectionResult {
            catalog: SelectionCatalogProvenance {
                server_catalog_etag: etag,
                server_catalog_fetched_unix: Some(fetched_unix),
                group_catalog_revision: group
                    .as_ref()
                    .map(|_| protonwire_core::groups::catalog_revision().to_owned()),
            },
            group,
            selector,
            hard_filters: HardFiltersReport {
                considered: outcome.report.considered(),
                survivors: outcome.report.survivors(),
                stages: stage_reports(&outcome.report),
            },
            physical_country,
            winner: SelectedServer {
                id: winner.server.id.clone(),
                name: winner.server.name.clone(),
                entry_country: winner.server.entry_country.clone(),
                exit_country: winner.server.exit_country.clone(),
                city: winner.server.city.clone(),
                tier: winner.server.tier,
                signals: WinnerSignals {
                    provenance: provenance.to_owned(),
                    proton_score: signals.proton_score,
                    load: signals.load,
                    latency_ms: signals.latency.map(|latency| latency.as_millis() as u64),
                    weighted: signals.weighted.map(|breakdown| WeightedBreakdownWire {
                        load_term: breakdown.load_term,
                        latency_term: breakdown.latency_term,
                        stability_term: breakdown.stability_term,
                        feature_match_term: breakdown.feature_match_term,
                        history_term: breakdown.history_term,
                        total: breakdown.total,
                    }),
                },
            },
            requested_features,
            // FR-23T's difference (Codex PR#9 round 8, P2):
            // requested-but-not-applied. Required features are
            // satisfy-or-refuse (their difference is empty by
            // construction); the OPTIONAL arm is prefer-not-require —
            // the ranking may legitimately prefer a server lacking
            // one, and the difference REPORTS it through the core's
            // one evaluation vocabulary, never a hard-coded empty
            // claiming every request was satisfied. The
            // connection-plane family stays M4's (FR-23E's boundary).
            feature_difference: modifiers
                .optional_features
                .iter()
                .filter(|feature| {
                    !protonwire_core::selection::feature_holds(
                        winner.server,
                        wire_feature(**feature),
                        &context,
                    )
                })
                .map(|feature| feature.as_str().to_owned())
                .collect(),
        }))
    }

    /// The built-in group catalog with FR-23S availability (the
    /// `GroupsList` body). Served from core's registry — no network
    /// beyond the entitlement snapshot (FR-23R), no hard-coded lists
    /// (FR-23I). NETWORK-FREE (Codex PR#9 round 4, P2): the built-in
    /// listing reads only local state (the registry + the cached
    /// catalog) — the entitlement tier comes from the CACHED snapshot
    /// when one exists and is unknown otherwise (the listing reports
    /// the honest unknown rather than initiating API traffic or
    /// blocking on a slow entitlement service).
    pub fn groups_catalog(&self) -> Result<GroupsCatalog, RpcError> {
        let cached = self.cached_catalog()?;
        let weights = self.balanced_weights();
        let account_tier = self.cached_entitlement_tier();
        let groups = protonwire_core::groups::all_groups()
            .iter()
            .map(|entry| {
                let availability = self.group_availability(
                    cached.as_ref().map(|(_, _, document)| document),
                    entry,
                    &weights,
                    account_tier,
                );
                group_summary(entry, availability)
            })
            .collect();
        Ok(GroupsCatalog {
            catalog_revision: protonwire_core::groups::catalog_revision().to_owned(),
            taxonomy_revision: protonwire_core::groups::taxonomy_revision().to_owned(),
            groups,
        })
    }

    /// One group's FR-23S availability: resolve + hard-filter over the
    /// cached catalog (no ranking — availability is not an ordering
    /// question, so the official missing-score refusal cannot pollute
    /// it). The account-entitlement tier composes like every select
    /// (FR-23P): a paid-location group under a free account reports
    /// the precise `account-tier` reason, never a false "available".
    fn group_availability(
        &self,
        catalog: Option<&CatalogDocument>,
        entry: &protonwire_core::groups::GroupEntry,
        weights: &WeightedSignals,
        account_tier: Option<i8>,
    ) -> GroupAvailability {
        let Some(catalog) = catalog else {
            return GroupAvailability {
                available: false,
                reason: Some("no-catalog".into()),
            };
        };
        // The GROUP-LEVEL entitlement gate (Codex PR#9 round 6, P2):
        // a PaidLocationSelection group is unavailable to non-paid
        // plans regardless of member tiers — resolve() refuses the
        // same request, and availability must agree with it (the
        // tier-0-in-region shape read available under a cached free
        // snapshot even though selecting it refuses). The cached
        // snapshot's plan_tier is the network-free source; None (no
        // snapshot) leaves the tier unknown — the paid-location answer
        // is then unknown-unavailable, never a false available.
        if entry.entitlement == protonwire_core::groups::GroupEntitlement::PaidLocationSelection {
            let paid = self
                .entitlement
                .cached_snapshot()
                .as_ref()
                .map(|snapshot| snapshot.plan_tier == Some(PlanTier::Paid));
            match paid {
                Some(true) => {}
                Some(false) => {
                    return GroupAvailability {
                        available: false,
                        reason: Some("entitlement".into()),
                    };
                }
                None => {
                    return GroupAvailability {
                        available: false,
                        reason: Some("entitlement-composition-missing".into()),
                    };
                }
            }
        }
        let cached_country = self.cached_location_country();
        let sources = PhysicalCountrySources {
            explicit_request: None,
            config: self.config.connection_groups.physical_country.as_deref(),
            cached_location: cached_country.as_deref(),
        };
        // No v1 group carries a PF constraint; the composition stays
        // uncomposed so a future PF-requiring group reports the
        // missing-composition reason rather than passing.
        let context = SelectionContext {
            account_tier,
            ..SelectionContext::default()
        };
        match resolve_group(entry.id, None, &sources, weights) {
            Ok(resolved) => {
                // The capability gate's availability twin (Codex
                // PR#9 round 8): a group whose resolved request names
                // a plan-gated capability (the secure-core group's
                // routed target; any p2p/tor constraint a group
                // merges) reports the SAME entitlement reasons
                // resolve() refuses with — availability agrees with
                // the gate (the round-6 invariant), read from the
                // CACHED snapshot (the listing's network-free
                // contract).
                if let Some((_, allowance)) = Self::unmet_capability(
                    self.entitlement.cached_snapshot().as_ref(),
                    &resolved.request,
                ) {
                    return unavailable(if allowance.is_some() {
                        "entitlement"
                    } else {
                        "entitlement-composition-missing"
                    });
                }
                match protonwire_core::selection::filter_candidates(
                    catalog,
                    &resolved.request,
                    &context,
                ) {
                    Ok((survivors, _)) if !survivors.is_empty() => GroupAvailability {
                        available: true,
                        reason: None,
                    },
                    Ok((_, report)) => {
                        // FR-23S's "precise entitlement" reason: when the
                        // tier stage is what emptied the pool, that is the
                        // availability answer — not the generic
                        // no-eligible-server.
                        let tier_bound = report.stages().iter().any(|(stage, count)| {
                            *stage == protonwire_core::selection::FilterStage::AccountTier
                                && *count > 0
                        });
                        if tier_bound {
                            unavailable("account-tier")
                        } else {
                            unavailable("no-eligible-server")
                        }
                    }
                    Err(SelectionError::PhysicalCountryRequired) => {
                        unavailable("physical-country-required")
                    }
                    Err(SelectionError::RequiresEntitlementComposition) => {
                        unavailable("entitlement-composition-missing")
                    }
                    Err(_) => unavailable("no-eligible-server"),
                }
            }
            // Registry-internal resolution failures (none constructible
            // from the frozen catalog with a None override) stay in the
            // no-eligible-server family.
            Err(_) => unavailable("no-eligible-server"),
        }
    }

    /// One group's full definition (the `GroupShow` body); the typed
    /// unknown-group refusal rides InvalidParams.
    pub fn group_details(&self, id: &str) -> Result<Box<GroupDetails>, RpcError> {
        let Some(entry) = protonwire_core::groups::group(id) else {
            return Err(RpcError::new(
                RpcErrorCode::InvalidParams,
                format!("unknown group `{id}`: not part of the canonical catalog"),
            ));
        };
        let weights = self.balanced_weights();
        let availability = self.group_availability(
            self.cached_catalog()?
                .as_ref()
                .map(|(_, _, document)| document),
            entry,
            &weights,
            self.cached_entitlement_tier(),
        );
        let (target, target_detail) = group_target_render(&entry.target);
        Ok(Box::new(GroupDetails {
            summary: group_summary(entry, availability),
            immutable: entry.immutable,
            connection_type: entry.connection_type.map(|kind| kind.as_str().to_owned()),
            target,
            target_detail,
            protocol_override: entry.protocol_override.map(protocol_token),
            connection_overrides: entry
                .connection_overrides
                .iter()
                .map(|(key, value)| [(*key).to_owned(), (*value).to_owned()])
                .collect(),
            selection_authority: entry
                .selection_authority
                .map(|authority| (*authority).to_owned()),
            sources: entry
                .sources
                .iter()
                .map(|source| (*source).to_owned())
                .collect(),
        }))
    }
}

/// The unavailable arm's constructor (keeps the match above flat).
fn unavailable(reason: &str) -> GroupAvailability {
    GroupAvailability {
        available: false,
        reason: Some(reason.to_owned()),
    }
}

/// One registry entry's [`GroupSummary`] projection — the one mapping
/// the `GroupsList` row and the `GroupShow` summary share, so a
/// registry field lands in exactly one place (the FilterStage::STAGES
/// precedent).
fn group_summary(
    entry: &protonwire_core::groups::GroupEntry,
    availability: GroupAvailability,
) -> GroupSummary {
    GroupSummary {
        id: entry.id.to_owned(),
        label: entry.label.to_owned(),
        origin: entry.origin.as_str().to_owned(),
        definition_source: entry.definition_source.as_str().to_owned(),
        entitlement: entry.entitlement.as_str().to_owned(),
        ranking_policy: entry.ranking_policy.as_str().to_owned(),
        allowed_ranking_overrides: entry
            .allowed_ranking_overrides
            .iter()
            .map(|policy| policy.as_str().to_owned())
            .collect(),
        availability,
    }
}

/// The transport executor (FR-19B): TCP connect-timing under the
/// default `tcp-udp` transport. The `icmp` opt-in is a config VALUE
/// this build honors fail-closed: the raw-socket executor is not wired
/// (CAP_NET_RAW is never assumed), so every probe observes nothing and
/// the latency ranking refuses on its data requirement — never a
/// fabricated RTT.
///
/// The executor also carries the round's TOTAL deadline (the Codex
/// PR-9 bound): each probe's timeout SHRINKS to the remaining budget
/// (a single in-flight connect cannot overrun the round), and the
/// `cancelled` seam `run_planned` polls between endpoints stops the
/// run at the deadline — the answered prefix survives, the unprobed
/// fall to the FR-18 shortlist boundary.
struct TransportExecutor<'a> {
    transport: ProbeTransport,
    timeout: Duration,
    endpoints: BTreeMap<String, SocketAddr>,
    connect: &'a dyn Fn(SocketAddr, Duration) -> Option<Duration>,
    /// When the whole round expires.
    round_deadline: Instant,
}

impl ProbeExecutor for TransportExecutor<'_> {
    fn probe(&mut self, endpoint: &str) -> Option<Duration> {
        match self.transport {
            ProbeTransport::TcpUdp => {
                // No logging here: the id→address mapping is never
                // written to the log (the PR-3 review's sec item).
                let addr = self.endpoints.get(endpoint)?;
                let remaining = self
                    .round_deadline
                    .saturating_duration_since(Instant::now());
                let timeout = self.timeout.min(remaining);
                (self.connect)(*addr, timeout)
            }
            ProbeTransport::Icmp => None,
        }
    }

    fn cancelled(&mut self) -> bool {
        Instant::now() >= self.round_deadline
    }
}

/// Resolves a logical id to the probe endpoint (an online physical's
/// per-protocol IPv4 + port, preferring WireGuard-UDP; the legacy
/// `EntryIP` shape falls back to port 443). Unresolvable ids return
/// `None` — absent data, never a guess.
fn probe_endpoint(catalog: &CatalogDocument, logical_id: &str) -> Option<SocketAddr> {
    let server = catalog
        .logical_servers
        .iter()
        .find(|server| server.id == logical_id)?;
    for physical in server.servers.iter().filter(|p| p.is_online()) {
        if let Some(map) = physical.entry_per_protocol.as_ref() {
            for endpoint in [
                map.wireguard_udp.as_ref(),
                map.wireguard_tcp.as_ref(),
                map.wireguard_tls.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                // A port-less endpoint map is skipped, not fatal: the
                // next protocol's map may carry one.
                if let Some(port) = endpoint.ports.as_ref().and_then(|ports| ports.first()) {
                    return format!("{}:{}", endpoint.ipv4, port).parse().ok();
                }
            }
        }
        if let Some(ip) = physical.entry_ip.as_deref() {
            return format!("{ip}:443").parse().ok();
        }
    }
    None
}

/// Maps the wire feature vocabulary onto the core's.
fn wire_features(
    required: &[SelectionFeature],
    optional: &[SelectionFeature],
) -> (Vec<FeatureConstraint>, Vec<FeatureConstraint>) {
    (
        required.iter().copied().map(wire_feature).collect(),
        optional.iter().copied().map(wire_feature).collect(),
    )
}

/// Maps ONE wire feature token onto the core's vocabulary (the
/// slice-level [`wire_features`] and the FR-23T difference report
/// share this — one mapping, never a second table).
fn wire_feature(feature: SelectionFeature) -> FeatureConstraint {
    match feature {
        SelectionFeature::P2p => FeatureConstraint::P2p,
        SelectionFeature::Tor => FeatureConstraint::Tor,
        SelectionFeature::SecureCore => FeatureConstraint::SecureCore,
        SelectionFeature::Streaming => FeatureConstraint::Streaming,
        SelectionFeature::Ipv6 => FeatureConstraint::Ipv6,
        SelectionFeature::PortForwarding => FeatureConstraint::PortForwarding,
    }
}

/// Maps the wire protocol vocabulary onto the core's.
fn wire_protocol(protocol: Option<SelectionProtocol>) -> Option<ProtocolConstraint> {
    protocol.map(|protocol| match protocol {
        SelectionProtocol::WireguardUdp => ProtocolConstraint::WireguardUdp,
        SelectionProtocol::WireguardTcp => ProtocolConstraint::WireguardTcp,
        SelectionProtocol::Stealth => ProtocolConstraint::Stealth,
    })
}

fn protocol_token(protocol: ProtocolConstraint) -> String {
    match protocol {
        ProtocolConstraint::WireguardUdp => "wireguard-udp",
        ProtocolConstraint::WireguardTcp => "wireguard-tcp",
        ProtocolConstraint::Stealth => "stealth",
    }
    .to_owned()
}

/// Merges the §9.3 selection-plane modifiers into a group-resolved
/// request (FR-23P's user-controlled stages, the Codex PR-9 P1:
/// pre-fix the group arm used `resolved.request` unchanged — every
/// parsed modifier was silently dropped while the result echoed it).
///
/// Precedence, per FR-23P's stage discipline:
///
/// - **Exclusions** (country/state/city/server): UNION — the group's
///   own lists and the user's both eliminate (either refusing is a
///   silent downgrade of an explicit user constraint).
/// - **Required/optional features**: UNION — the group's constraints
///   and the user's must all hold.
/// - **Protocol**: the group's declared override is its official
///   semantics (T-33's `RankingOverrideForbidden` precedent —
///   request-time overrides may not change them); a user protocol
///   that CONFLICTS with a declared override is a typed refusal
///   naming both — never a silent drop of either side. With no
///   declared override, the user's protocol applies.
///
/// The physical-country and ranking modifiers do not pass through
/// here: `--physical-country` composes through FR-23Q's sources and
/// `--by` through the registry's override discipline inside
/// [`resolve_group`] — both BEFORE this merge.
fn merge_group_modifiers(
    group_id: &str,
    request: SelectionRequest,
    modifiers: &SelectionModifiers,
    required_features: Vec<FeatureConstraint>,
    optional_features: Vec<FeatureConstraint>,
    required_protocol: Option<ProtocolConstraint>,
) -> Result<SelectionRequest, RpcError> {
    // The protocol precedence first: a conflicting pair refuses typed
    // before anything is merged (the refusal describes the conflict,
    // not a half-merged request).
    if let (Some(declared), Some(requested)) =
        (request.constraints.required_protocol, required_protocol)
        && declared != requested
    {
        return Err(RpcError::new(
            RpcErrorCode::InvalidParams,
            format!(
                "group `{group_id}` declares the `{}` protocol override but the request requires \
                 `{}` — a group's declared protocol is its official semantics (FR-23P); pass the \
                 matching protocol or select the target directly",
                protocol_token(declared),
                protocol_token(requested)
            ),
        ));
    }
    let mut request = request;
    request
        .constraints
        .excluded_countries
        .extend(modifiers.excluded_countries.iter().cloned());
    request
        .constraints
        .excluded_states
        .extend(modifiers.excluded_states.iter().cloned());
    request
        .constraints
        .excluded_cities
        .extend(modifiers.excluded_cities.iter().cloned());
    request
        .constraints
        .excluded_servers
        .extend(modifiers.excluded_servers.iter().cloned());
    request
        .constraints
        .required_features
        .extend(required_features);
    request
        .constraints
        .optional_features
        .extend(optional_features);
    // Union for protocol: the declared override (when one exists) kept,
    // the user's applied otherwise — the conflict arm above already
    // refused every disagreeing pair.
    if request.constraints.required_protocol.is_none() {
        request.constraints.required_protocol = required_protocol;
    }
    Ok(request)
}

/// The direct-target arm: the PRD 9.2 grammar mapped onto the core
/// vocabulary. `--by` parses through the core's mode vocabulary (the
/// forbidden throughput signals reject typed there); a balanced policy
/// runs under the composed weights (P2-2).
fn direct_request(
    target: &ConnectTarget,
    modifiers: &SelectionModifiers,
    required_features: Vec<FeatureConstraint>,
    optional_features: Vec<FeatureConstraint>,
    required_protocol: Option<ProtocolConstraint>,
    balanced_weights: &WeightedSignals,
) -> Result<SelectionRequest, RpcError> {
    let policy = match (target, modifiers.by.as_deref()) {
        (_, Some(mode)) => RankingPolicy::parse(mode).map_err(selection_error_to_rpc)?,
        (ConnectTarget::Random, None) => RankingPolicy::Random,
        _ => RankingPolicy::Official,
    };
    let policy = match policy {
        RankingPolicy::Balanced { .. } => RankingPolicy::Balanced {
            weights: *balanced_weights,
        },
        other => other,
    };
    let (core_target, extra_required) = match target {
        ConnectTarget::Fastest | ConnectTarget::Random => (Target::Fastest, Vec::new()),
        ConnectTarget::Country { country } => (Target::Country(country.clone()), Vec::new()),
        ConnectTarget::State { state_or_region } => {
            (Target::State(state_or_region.clone()), Vec::new())
        }
        ConnectTarget::City { city } => (Target::City(city.clone()), Vec::new()),
        ConnectTarget::Server { server } => (Target::Server(server.clone()), Vec::new()),
        ConnectTarget::Gateway { gateway } => (Target::Gateway(gateway.clone()), Vec::new()),
        ConnectTarget::Special { class } => (
            Target::Fastest,
            vec![match class {
                SpecialClass::P2p => FeatureConstraint::P2p,
                SpecialClass::Tor => FeatureConstraint::Tor,
            }],
        ),
        ConnectTarget::SecureCore {
            entry_country,
            exit_country,
        } => (
            Target::SecureCore {
                entry_country: entry_country.clone(),
                exit_country: exit_country.clone(),
            },
            Vec::new(),
        ),
        ConnectTarget::Group { .. } => {
            unreachable!("the group arm resolves through the registry before this mapping")
        }
        ConnectTarget::Profile { profile } => {
            return Err(RpcError::new(
                RpcErrorCode::NotImplemented,
                format!(
                    "profile targets land in milestone 6 (profile `{profile}` cannot be \
                     resolved by the selection surface)"
                ),
            ));
        }
    };
    let mut required_features = required_features;
    required_features.extend(extra_required);
    Ok(SelectionRequest {
        target: core_target,
        policy,
        constraints: Constraints {
            excluded_countries: modifiers.excluded_countries.clone(),
            excluded_states: modifiers.excluded_states.clone(),
            excluded_cities: modifiers.excluded_cities.clone(),
            excluded_servers: modifiers.excluded_servers.clone(),
            required_features,
            optional_features,
            required_protocol,
            ..Constraints::default()
        },
    })
}

/// The direct-target selector rendering (the group arm renders its
/// own).
fn direct_selector(target: &ConnectTarget, policy: &RankingPolicy) -> ResolvedSelector {
    let (token, detail) = match target {
        ConnectTarget::Fastest => ("fastest", None),
        ConnectTarget::Random => ("random", None),
        ConnectTarget::Country { country } => ("country", Some(country.clone())),
        ConnectTarget::State { state_or_region } => ("state", Some(state_or_region.clone())),
        ConnectTarget::City { city } => ("city", Some(city.clone())),
        ConnectTarget::Server { server } => ("server", Some(server.clone())),
        ConnectTarget::Gateway { gateway } => ("gateway", Some(gateway.clone())),
        ConnectTarget::Special { class } => (
            match class {
                SpecialClass::P2p => "p2p",
                SpecialClass::Tor => "tor",
            },
            None,
        ),
        ConnectTarget::SecureCore {
            entry_country,
            exit_country,
        } => (
            "secure-core",
            Some(match (entry_country, exit_country) {
                (Some(entry), Some(exit)) => format!("{entry}->{exit}"),
                (Some(entry), None) => format!("{entry}->fastest"),
                (None, Some(exit)) => format!("fastest->{exit}"),
                (None, None) => "fastest->fastest".to_owned(),
            }),
        ),
        ConnectTarget::Group { group_id } => ("group", Some(group_id.clone())),
        ConnectTarget::Profile { profile } => ("profile", Some(profile.clone())),
    };
    ResolvedSelector {
        target: token.to_owned(),
        detail,
        policy: policy_token(policy),
    }
}

/// The policy token for the selector rendering.
fn policy_token(policy: &RankingPolicy) -> String {
    match policy {
        RankingPolicy::Official => "official",
        RankingPolicy::Balanced { .. } => "balanced",
        RankingPolicy::LowestLoad => "load",
        RankingPolicy::Latency => "latency",
        RankingPolicy::Random => "random",
    }
    .to_owned()
}

/// The group target's rendering for `group show`.
fn group_target_render(target: &GroupTarget) -> (String, Option<String>) {
    match target {
        GroupTarget::Fastest {
            exclude_physical_country,
        } => (
            "fastest".to_owned(),
            exclude_physical_country.then(|| "excluding-physical-country".to_owned()),
        ),
        GroupTarget::FastestInCountry { country } => {
            ("fastest-in-country".to_owned(), Some((*country).to_owned()))
        }
        GroupTarget::FastestInRegion { region } => {
            ("fastest-in-region".to_owned(), Some((*region).to_owned()))
        }
        GroupTarget::Random => ("random".to_owned(), None),
        GroupTarget::SecureCore {
            entry_country,
            exit_country,
        } => (
            "secure-core".to_owned(),
            Some(format!("{entry_country}->{exit_country}")),
        ),
    }
}

/// Maps a group-resolution refusal onto the RPC taxonomy.
fn group_error_to_rpc(error: protonwire_core::groups::GroupError) -> RpcError {
    RpcError::new(RpcErrorCode::InvalidParams, error.to_string())
}

/// The FR-22 report's nonzero stages in evaluation order — the ONE
/// projection behind both wire forms (the result's typed
/// [`HardFiltersReport`] and the refusal `details` payload below), so
/// the two can never disagree about which stages carry what.
fn stage_reports(report: &protonwire_core::selection::EliminationReport) -> Vec<StageReport> {
    report
        .stages()
        .iter()
        .filter(|(_, eliminated)| *eliminated > 0)
        .map(|(stage, eliminated)| StageReport {
            stage: stage.to_string(),
            eliminated: *eliminated,
        })
        .collect()
}

/// The FR-22 elimination report as `details` JSON (the structured
/// no-eligible-server payload).
fn report_details(
    report: &protonwire_core::selection::EliminationReport,
) -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "considered": report.considered(),
        "survivors": report.survivors(),
        "stages": stage_reports(report),
    }))
}

/// Maps the pure core's typed refusals onto the RPC taxonomy (PRD
/// 9.8).
fn selection_error_to_rpc(error: SelectionError) -> RpcError {
    match error {
        SelectionError::ConstraintsNotSatisfied { report } => RpcError {
            code: RpcErrorCode::NoEligibleServer,
            message: format!("no eligible server: {report}"),
            details: report_details(&report),
        },
        SelectionError::ExactServerUnavailable { name, stage } => RpcError {
            code: RpcErrorCode::NoEligibleServer,
            message: format!(
                "exact server `{name}` is not selectable ({stage}): exact requests never fall \
                 back to another server"
            ),
            details: Some(serde_json::json!({
                "stage": stage.to_string(),
                "server": name,
            })),
        },
        SelectionError::OfficialScoreUnavailable { .. }
        | SelectionError::LatencyDataUnavailable { .. } => {
            RpcError::new(RpcErrorCode::NoEligibleServer, error.to_string())
        }
        SelectionError::PhysicalCountryRequired => {
            RpcError::new(RpcErrorCode::InvalidParams, error.to_string())
        }
        SelectionError::RequiresEntitlementComposition => RpcError {
            code: RpcErrorCode::EntitlementMissing,
            message: format!(
                "{}: the entitlement adapter is not installed (the session lane wires it); \
                 the seam refuses typed rather than guessing",
                error
            ),
            details: None,
        },
        SelectionError::RandomEntropyRequired => RpcError::new(
            RpcErrorCode::Internal,
            "the daemon failed to supply the random policy's entropy",
        ),
        SelectionError::UnsupportedRankingSignal { .. }
        | SelectionError::InvalidRankingMode(_)
        | SelectionError::InvalidWeights(_)
        | SelectionError::InvalidCountry(_)
        | SelectionError::StandardFleetFeatureContradiction
        | SelectionError::SecureCoreEntryEqualsExit { .. }
        | SelectionError::SecureCoreOnlyConstraints => {
            RpcError::new(RpcErrorCode::InvalidParams, error.to_string())
        }
    }
}

/// [`selection_error_to_rpc`] with the PF empty-capability composition's
/// honest explanation attached when the request carried the
/// port-forwarding constraint: the bare FR-22 report says
/// "required-features" without saying WHY nothing passed, so the
/// ConstraintsNotSatisfied message names the M6 capability source and
/// the structured report still rides `details`.
fn selection_error_to_rpc_pf_explained(error: SelectionError, pf_requested: bool) -> RpcError {
    if pf_requested && let SelectionError::ConstraintsNotSatisfied { ref report } = error {
        let mut enriched = RpcError::new(
            RpcErrorCode::NoEligibleServer,
            format!(
                "no eligible server: {report}; the port-forwarding constraint \
                 eliminated every candidate because no per-server \
                 port-forwarding capability source exists yet (M6's NAT-PMP \
                 lane supplies it — the composition is honestly empty, never \
                 fabricated)"
            ),
        );
        enriched.details = report_details(report);
        return enriched;
    }
    selection_error_to_rpc(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protonwire_frontend_api::SelectionFeature;
    use protonwire_frontend_api::SelectionProtocol;

    /// A synthetic catalog body: 6 logicals over 5 countries — GB pair
    /// (scores invert loads), CH, a Secure Core CH→SE route, a P2P GB
    /// server, and JP (Asia) for the regional groups. Every physical
    /// is online with a WireGuard-UDP endpoint on TEST-NET-1 (never
    /// routable — the injected connect seam decides answers, never the
    /// network).
    fn catalog_body() -> String {
        // A test fixture row (one logical per call; the arity is the row).
        #[allow(clippy::too_many_arguments)]
        fn logical(
            id: &str,
            name: &str,
            entry: &str,
            exit: &str,
            tier: i8,
            features: u64,
            load: i8,
            score: f32,
        ) -> serde_json::Value {
            serde_json::json!({
                "ID": id, "Name": name, "City": "City", "State": null,
                "EntryCountry": entry, "ExitCountry": exit, "Domain": null,
                "Tier": tier, "Features": features, "Status": 1,
                "Load": load, "Score": score, "HostCountry": null,
                "GatewayName": null, "Translations": null,
                "Servers": [{
                    "ID": format!("{id}-p0"), "EntryIP": null, "ExitIP": null,
                    "Domain": "phys.example", "Status": 1, "Label": "",
                    "X25519PublicKey": null, "Signature": null, "Generation": null,
                    "ServicesDownReason": null,
                    "EntryPerProtocol": {
                        "WireGuardUDP": { "IPv4": "192.0.2.10", "Ports": [443] },
                        "WireGuardTCP": null, "WireGuardTLS": null,
                        "OpenVPNUDP": null, "OpenVPNTCP": null
                    }
                }]
            })
        }
        serde_json::json!({
            "Code": 1000, "Error": "", "StatusID": "test-status",
            "LogicalServers": [
                logical("id-GB#1", "GB#1", "GB", "GB", 0, 0, 20, 1.05),
                logical("id-GB#2", "GB#2", "GB", "GB", 0, 0, 80, 2.00),
                logical("id-CH#10", "CH#10", "CH", "CH", 2, 0, 42, 1.40),
                logical("id-CH-SE#1", "CH-SE#1", "CH", "SE", 2, 1, 30, 1.10),
                logical("id-GB-P2P", "GB-P2P", "GB", "GB", 0, 4, 10, 1.20),
                logical("id-JP#1", "JP#1", "JP", "JP", 2, 0, 50, 1.50),
            ]
        })
        .to_string()
    }

    /// The engine under test: the planted catalog served past the
    /// fs_trust walk (the F1 chown-seam precedent — the walk itself is
    /// root-gated by design and pinned by the store/S9 suites; these
    /// walls pin COMPOSITION), an injectable clock, and an injectable
    /// connect seam.
    fn engine_over(
        config: SystemConfig,
        now_ms: u64,
        connect: impl Fn(SocketAddr, Duration) -> Option<Duration> + Send + Sync + 'static,
    ) -> SelectionEngine {
        let mut engine = SelectionEngine::new(
            Arc::new(config),
            Path::new("/hermetic-unused"),
            Path::new("/hermetic-unused"),
        );
        engine.now_ms = Box::new(move || now_ms);
        engine.connect = Box::new(connect);
        engine.catalog_read = Box::new(|| {
            Ok(Some(CachedCatalog {
                schema_version: 1,
                etag: Some("\"test-rev-1\"".to_owned()),
                fetched_unix: 1_771_000_000,
                body: catalog_body(),
            }))
        });
        engine.location_read = Box::new(|| Ok(None));
        engine
    }

    /// As [`engine_over`], with a location cache answering `country`.
    fn engine_with_location(config: SystemConfig, country: &'static str) -> SelectionEngine {
        let mut engine = engine_over(config, 1_000_000, never_answers);
        engine.location_read = Box::new(move || {
            Ok(Some(CachedLocation {
                schema_version: 1,
                fetched_unix: 1_771_000_000,
                ip: String::new(),
                country: country.to_owned(),
                isp: String::new(),
                latitude: None,
                longitude: None,
            }))
        });
        engine
    }

    /// An engine with NO cached catalog (the nothing-yet state).
    fn engine_without_catalog() -> SelectionEngine {
        let mut engine = engine_over(SystemConfig::default(), 1_000_000, never_answers);
        engine.catalog_read = Box::new(|| Ok(None));
        engine
    }

    fn default_engine() -> SelectionEngine {
        engine_over(SystemConfig::default(), 1_000_000, never_answers)
    }

    fn never_answers(_addr: SocketAddr, _timeout: Duration) -> Option<Duration> {
        None
    }

    fn modifiers() -> SelectionModifiers {
        SelectionModifiers::default()
    }

    fn country(code: &str) -> ConnectTarget {
        ConnectTarget::Country {
            country: code.to_owned(),
        }
    }

    /// The happy path: a direct official select over the planted
    /// catalog answers with the FULL FR-23T field set — the revisions,
    /// the resolved selector, the FR-22 report, and the winning server
    /// with its catalog-only signals.
    #[test]
    fn direct_official_select_carries_the_fr23t_field_set() {
        let engine = default_engine();
        let result = engine
            .resolve(&country("GB"), &modifiers())
            .expect("the planted catalog selects");
        assert_eq!(
            result.catalog.server_catalog_etag.as_deref(),
            Some("\"test-rev-1\"")
        );
        assert_eq!(
            result.catalog.server_catalog_fetched_unix,
            Some(1_771_000_000)
        );
        assert!(result.catalog.group_catalog_revision.is_none());
        assert!(result.group.is_none());
        assert_eq!(result.selector.target, "country");
        assert_eq!(result.selector.detail.as_deref(), Some("GB"));
        assert_eq!(result.selector.policy, "official");
        assert_eq!(result.winner.name, "GB#1", "official = score ascending");
        assert_eq!(result.winner.signals.provenance, "catalog-only");
        assert_eq!(result.winner.signals.proton_score, Some(1.05));
        assert_eq!(result.hard_filters.considered, 6);
        assert_eq!(
            result.hard_filters.survivors, 3,
            "GB#1, GB#2, and the P2P GB server"
        );
        // The non-GB logicals: the SC route charges to server-type
        // (first eliminating stage), the other two to geography.
        assert!(
            result
                .hard_filters
                .stages
                .iter()
                .any(|stage| stage.stage == "target-geography" && stage.eliminated == 2)
        );
        assert!(
            result
                .hard_filters
                .stages
                .iter()
                .any(|stage| stage.stage == "server-type" && stage.eliminated == 1)
        );
        assert!(result.physical_country.is_none());
        assert!(result.feature_difference.is_empty());
    }

    /// No cached catalog: the typed refusal telling the caller to
    /// refresh — selection never fabricates an empty catalog (FR-23R).
    #[test]
    fn select_without_a_cached_catalog_refuses_typed() {
        let engine = engine_without_catalog();
        let error = engine
            .resolve(&country("GB"), &modifiers())
            .expect_err("nothing is cached");
        assert_eq!(error.code, RpcErrorCode::NoEligibleServer);
        assert!(
            error.message.contains("no server catalog is cached"),
            "guidance to refresh: {error}"
        );
    }

    /// FR-23H at the daemon: a PF request with NO entitlement adapter
    /// installed (the session lane's cell is empty) is the typed
    /// missing-composition refusal — never a pass, never a guess.
    #[test]
    fn pf_request_refuses_the_missing_composition_without_an_adapter() {
        let engine = default_engine();
        let error = engine
            .resolve(
                &country("GB"),
                &SelectionModifiers {
                    required_features: vec![SelectionFeature::PortForwarding],
                    ..modifiers()
                },
            )
            .expect_err("the uncomposed seam must refuse");
        assert_eq!(error.code, RpcErrorCode::EntitlementMissing);
        assert!(
            error.message.contains("port-forwarding"),
            "the refusal names the constraint: {error}"
        );
        assert!(
            error.message.contains("capability"),
            "the refusal names BOTH uncomposed seams: {error}"
        );
    }

    /// FR-87 at the daemon: under an INSTALLED paid entitlement, the
    /// honest empty capability composition eliminates every candidate
    /// — the refusal explains the M6 source, and the structured FR-22
    /// report rides `details`.
    #[test]
    fn pf_request_under_a_paid_entitlement_finds_no_capable_server() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::paid()));
        let error = engine
            .resolve(
                &country("GB"),
                &SelectionModifiers {
                    required_features: vec![SelectionFeature::PortForwarding],
                    ..modifiers()
                },
            )
            .expect_err("the empty capability set must refuse");
        assert_eq!(error.code, RpcErrorCode::NoEligibleServer);
        assert!(
            error
                .message
                .contains("no per-server port-forwarding capability source"),
            "the honest explanation: {error}"
        );
        assert!(
            error.message.contains("M6"),
            "the milestone that supplies the source: {error}"
        );
        let details = error.details.expect("the FR-22 report rides details");
        let required = details["stages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stage| stage["stage"] == "required-features")
            .expect("the eliminating stage is named");
        assert_eq!(
            required["eliminated"], 3,
            "every GB candidate failed the PF stage"
        );
    }

    /// An installed FREE entitlement refuses at the feature stage with
    /// the entitlement-first explanation (the capability question is
    /// never reached for an unentitled account).
    #[test]
    fn pf_request_under_a_free_entitlement_refuses_on_entitlement() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::free()));
        let error = engine
            .resolve(
                &country("GB"),
                &SelectionModifiers {
                    required_features: vec![SelectionFeature::PortForwarding],
                    ..modifiers()
                },
            )
            .expect_err("an unentitled account must refuse");
        assert_eq!(error.code, RpcErrorCode::NoEligibleServer);
        let details = error.details.expect("the report rides details");
        assert!(
            details["stages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|stage| stage["stage"] == "required-features")
        );
    }

    /// Codex PR#9 round 7 (P2, the deadline clamp): the entitlement
    /// wait shares resolve()'s ONE request deadline — the CONFIGURED
    /// budget (6 s default; validation permits 9.5 s) only TIGHTENS
    /// the wait, never extends it past the deadline's remainder. A
    /// never-landing adapter under a nearly-spent deadline refuses at
    /// the remainder (fail-closed), not at the full budget — pre-fix
    /// the 6 s wait overran the 9 s deadline toward the IPC client's
    /// 10 s timeout before selection or reply work began.
    #[test]
    fn entitlement_wait_clamps_to_the_shared_request_deadline() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(NeverLandingEntitlements));
        let deadline = Instant::now() + Duration::from_millis(250);
        let start = Instant::now();
        let error = engine
            .entitlement_composition(deadline)
            .expect_err("the deadline's remainder bounds the wait");
        assert_eq!(error.code, RpcErrorCode::EntitlementMissing);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(2_000),
            "the wait clamps to the deadline's ~250 ms remainder (measured {elapsed:?}; the \
             pre-fix wait blocked the full configured 6 s budget, past the 9 s deadline)"
        );
    }

    /// The clamp never LOOSENS the wait (the other min() arm): when
    /// the deadline leaves ample room, the CONFIGURED budget still
    /// bounds it — here the 250 ms validation floor under a 60 s
    /// deadline, so the refusal arrives only after the budget spent.
    #[test]
    fn entitlement_wait_keeps_the_configured_budget_when_the_deadline_is_far() {
        let mut config = SystemConfig::default();
        config.server_selection.entitlement_fetch_budget_ms = 250;
        let engine = engine_over(config, 1_000_000, never_answers);
        engine
            .entitlement()
            .install(Arc::new(NeverLandingEntitlements));
        let deadline = Instant::now() + Duration::from_secs(60);
        let start = Instant::now();
        let error = engine
            .entitlement_composition(deadline)
            .expect_err("the configured budget still bounds the wait");
        assert_eq!(error.code, RpcErrorCode::EntitlementMissing);
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(240),
            "the full configured 250 ms budget elapsed before the refusal (measured \
             {elapsed:?})"
        );
        // The upper bound pins the min()'s OTHER arm: a mutant that
        // DROPS the configured budget (deadline replaces it) would
        // park this waiter the full 60 s deadline.
        assert!(
            elapsed < Duration::from_millis(2_000),
            "the configured budget (not the far deadline) bounds the wait (measured \
             {elapsed:?})"
        );
    }

    /// Codex PR#9 round 8 (P1, the capability gate): a FREE account's
    /// plan does not include the p2p/tor/secure-core capabilities
    /// (`FeatureAllowances`: `Some(plan is paid)`; the parity
    /// vocabulary `servers.p2p|tor|secure-core: entitlement: paid`) —
    /// a request NAMING one refuses typed (FR-23S's precise
    /// entitlement error), the same family shape as the gateway
    /// business gate and the paid-location gate. Pre-fix the tier
    /// stage was the only gate, so the fixture's tier-0 GB-P2P handed
    /// a free account a successful P2P selection.
    #[test]
    fn free_account_cannot_select_the_p2p_special_class() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::free()));
        let error = engine
            .resolve(
                &ConnectTarget::Special {
                    class: SpecialClass::P2p,
                },
                &modifiers(),
            )
            .expect_err("the free plan does not include the p2p capability");
        assert_eq!(error.code, RpcErrorCode::EntitlementMissing);
        assert!(
            error.message.contains("p2p capability"),
            "the refusal names the capability: {error}"
        );
    }

    /// The `--require` arm of the same gate.
    #[test]
    fn free_account_cannot_require_tor() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::free()));
        let error = engine
            .resolve(
                &ConnectTarget::Fastest,
                &SelectionModifiers {
                    required_features: vec![SelectionFeature::Tor],
                    ..modifiers()
                },
            )
            .expect_err("requiring tor is naming the capability");
        assert_eq!(error.code, RpcErrorCode::EntitlementMissing);
        assert!(error.message.contains("tor capability"), "{error}");
    }

    /// The `--prefer` arm (BOTH arms gate — the PF precedent: an
    /// optional request still weights ranking toward the capability,
    /// and the winner can carry it).
    #[test]
    fn free_account_cannot_prefer_p2p() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::free()));
        let error = engine
            .resolve(
                &ConnectTarget::Fastest,
                &SelectionModifiers {
                    optional_features: vec![SelectionFeature::P2p],
                    ..modifiers()
                },
            )
            .expect_err("preferring p2p is naming the capability");
        assert_eq!(error.code, RpcErrorCode::EntitlementMissing);
    }

    /// The routed Secure Core target names the secure-core capability.
    /// Pre-fix a free account reached the TIER stage's
    /// no-eligible-server refusal — the wrong error family for a plan
    /// gate (FR-23S: the precise entitlement error).
    #[test]
    fn free_account_cannot_select_secure_core_routing() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::free()));
        let error = engine
            .resolve(
                &ConnectTarget::SecureCore {
                    entry_country: None,
                    exit_country: None,
                },
                &modifiers(),
            )
            .expect_err("secure-core routing is a paid capability");
        assert_eq!(error.code, RpcErrorCode::EntitlementMissing);
        assert!(
            error.message.contains("secure-core capability") && error.message.contains("paid plan"),
            "the refusal names the capability and the plan: {error}"
        );
    }

    /// PAID keeps every special selection (the non-regression arm of
    /// the gate).
    #[test]
    fn paid_account_keeps_special_selections() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::paid()));
        let p2p = engine
            .resolve(
                &ConnectTarget::Special {
                    class: SpecialClass::P2p,
                },
                &modifiers(),
            )
            .expect("the paid plan includes p2p");
        assert_eq!(p2p.winner.name, "GB-P2P");
        let secure_core = engine
            .resolve(
                &ConnectTarget::SecureCore {
                    entry_country: None,
                    exit_country: None,
                },
                &modifiers(),
            )
            .expect("the paid plan includes secure-core routing");
        assert_eq!(secure_core.winner.name, "CH-SE#1");
    }

    /// The family semantics (gateway, regional, PF): no composed
    /// snapshot → fail-closed — the fourth member of the gate family
    /// refuses uncomposed capability requests too. Pre-fix the
    /// login-free p2p special selected GB-P2P.
    #[test]
    fn specials_without_a_composed_snapshot_refuse_fail_closed() {
        let engine = default_engine();
        let error = engine
            .resolve(
                &ConnectTarget::Special {
                    class: SpecialClass::P2p,
                },
                &modifiers(),
            )
            .expect_err("an uncomposed snapshot cannot prove the capability");
        assert_eq!(error.code, RpcErrorCode::EntitlementMissing);
    }

    /// Availability AGREES with the capability gate (the round-6
    /// invariant: never visible-available while connecting refuses):
    /// the secure-core group reads the entitlement reasons under a
    /// missing and a free cached snapshot, and available under a paid
    /// one.
    #[test]
    fn special_group_availability_agrees_with_the_capability_gate() {
        // No snapshot: unknown entitlement, fail-closed.
        let engine = default_engine();
        let listing = engine.groups_catalog().expect("the registry serves");
        let max_security = listing
            .groups
            .iter()
            .find(|group| group.id == "proton:max-security")
            .expect("the secure-core group is listed");
        assert!(!max_security.availability.available);
        assert_eq!(
            max_security.availability.reason.as_deref(),
            Some("entitlement-composition-missing")
        );

        // A FREE cached snapshot (one resolve primes the cache — the
        // round-6 pattern): the precise entitlement reason.
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::free()));
        let _ = engine.resolve(&country("CH"), &modifiers());
        let listing = engine.groups_catalog().expect("the registry serves");
        let max_security = listing
            .groups
            .iter()
            .find(|group| group.id == "proton:max-security")
            .expect("the secure-core group is listed");
        assert!(!max_security.availability.available);
        assert_eq!(
            max_security.availability.reason.as_deref(),
            Some("entitlement"),
            "free plans read the entitlement reason, never a false available"
        );

        // A PAID cached snapshot: available.
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::paid()));
        engine
            .resolve(&country("GB"), &modifiers())
            .expect("the paid resolve primes the cache");
        let listing = engine.groups_catalog().expect("the registry serves");
        let max_security = listing
            .groups
            .iter()
            .find(|group| group.id == "proton:max-security")
            .expect("the secure-core group is listed");
        assert!(max_security.availability.available);
    }

    /// Codex PR#9 round 8 (P2, the difference): optional features
    /// never eliminate (they feed the feature-match term), so the
    /// winner may legitimately lack one — FR-23T's
    /// `feature_difference` must REPORT it, never a hard-coded empty
    /// vector claiming every request was satisfied.
    #[test]
    fn optional_features_absent_from_the_winner_report_their_difference() {
        // Streaming carries no plan allowance (not in the gate's
        // vocabulary) — a login-free selection succeeds and the
        // winner lacks the bit: the difference says so.
        let engine = default_engine();
        let result = engine
            .resolve(
                &ConnectTarget::Fastest,
                &SelectionModifiers {
                    optional_features: vec![SelectionFeature::Streaming],
                    ..modifiers()
                },
            )
            .expect("optional features never eliminate");
        assert_eq!(result.winner.name, "GB#1", "official order");
        assert_eq!(
            result.feature_difference,
            vec!["streaming".to_owned()],
            "the requested-but-absent optional feature is reported"
        );

        // The p2p arm under a PAID plan (the gate passes): the
        // official-order winner GB#1 lacks the p2p bit GB-P2P carries.
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::paid()));
        let result = engine
            .resolve(
                &ConnectTarget::Fastest,
                &SelectionModifiers {
                    optional_features: vec![SelectionFeature::P2p],
                    ..modifiers()
                },
            )
            .expect("the paid plan may prefer p2p");
        assert_eq!(result.winner.name, "GB#1");
        assert_eq!(
            result.feature_difference,
            vec!["p2p".to_owned()],
            "preferred-but-absent is provenance, not silence"
        );
    }

    /// Codex PR-9 (P1, the entitlement tier): a FREE account's
    /// selection must never return a PAID-tier server. Pre-fix the
    /// context carried only the PF boolean — the full cached catalog
    /// reached `select()` unfiltered, so `country CH` (whose only
    /// member, CH#10, is tier 2) happily returned the paid server.
    /// The S8 `MaxTier` now composes onto the core's
    /// account-entitlement stage (FR-23P's own stage, ahead of online
    /// state) and the refusal's FR-22 report names it.
    #[test]
    fn free_account_selection_eliminates_paid_tier_servers() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::free()));
        let error = engine
            .resolve(&country("CH"), &modifiers())
            .expect_err("a free account cannot select the tier-2 CH#10");
        assert_eq!(error.code, RpcErrorCode::NoEligibleServer);
        let details = error.details.expect("the report rides details");
        let tier_stage = details["stages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stage| stage["stage"] == "account-tier")
            .expect("the eliminating stage is the entitlement tier");
        assert_eq!(
            tier_stage["eliminated"], 3,
            "every tier-2 logical (CH#10, CH-SE#1, JP#1) — the entitlement stage precedes \
             geography (FR-23P), so non-members above the tier charge here too"
        );
    }

    /// The same composition over a mixed field — now BOTH arms of the
    /// round-5 paid-location gate: a FREE account's fastest-europe
    /// REFUSES (choosing a location IS the paid capability); a PAID
    /// account's winner is a free-tier member with the FR-22 report
    /// accounting the other members to the account-tier stage.
    #[test]
    fn free_account_ranks_only_free_tier_members() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::free()));
        let error = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "protonwire:fastest-europe".into(),
                },
                &modifiers(),
            )
            .expect_err("a free account may not choose a location (the regional gate)");
        assert_eq!(error.code, RpcErrorCode::EntitlementMissing);
        assert!(
            error.message.contains("paid plan"),
            "the refusal names the capability: {error}"
        );

        // The tier-ranking half rides a NON-regional group (the
        // registry classifies fastest-country PlanDependent, not
        // PaidLocationSelection) so the free fixture still reaches
        // the account-tier stage.
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::free()));
        let result = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "proton:fastest-country".into(),
                },
                &modifiers(),
            )
            .expect("the non-regional group serves the free account");
        assert_eq!(result.winner.name, "GB#1", "official order over tier 0");
        assert_eq!(result.winner.tier, 0);
        assert!(
            result
                .hard_filters
                .stages
                .iter()
                .any(|stage| stage.stage == "account-tier" && stage.eliminated == 3),
            "every tier-2 logical is accounted to the entitlement tier (the stage precedes \
             geography): {:?}",
            result.hard_filters.stages
        );
    }

    /// A PAID account (MaxTier 3) keeps the full field — the stage is
    /// the account's, not a global paywall.
    #[test]
    fn paid_account_selection_includes_paid_tier_servers() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::paid()));
        let result = engine
            .resolve(&country("CH"), &modifiers())
            .expect("MaxTier 3 covers the tier-2 server");
        assert_eq!(result.winner.name, "CH#10");
        assert_eq!(result.winner.tier, 2);
    }

    /// FR-23S at the tier seam: a paid-location group (asia's only
    /// fixture member is tier 2) reports UNAVAILABLE under a free
    /// account with the precise entitlement reason — pre-fix the
    /// availability path ignored entitlements entirely and asia read
    /// available. Free-member groups (europe) stay available. The
    /// NETWORK-FREE listing (round 4, P2) uses the CACHED snapshot:
    /// the test primes it with one resolve first (which composes and
    /// stores), then the listing reads it without traffic.
    #[test]
    fn free_account_reports_paid_location_groups_unavailable() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::free()));
        // Prime the cached snapshot (one network composition — the
        // resolve that a logged-in session would have performed).
        drop(engine.resolve(&country("CH"), &modifiers()));
        let catalog = engine.groups_catalog().expect("the registry serves");
        let asia = catalog
            .groups
            .iter()
            .find(|group| group.id == "protonwire:fastest-asia")
            .unwrap();
        assert!(!asia.availability.available);
        assert_eq!(
            asia.availability.reason.as_deref(),
            Some("entitlement"),
            "the precise FR-23S entitlement reason"
        );
        let europe = catalog
            .groups
            .iter()
            .find(|group| group.id == "protonwire:fastest-europe")
            .unwrap();
        assert!(
            !europe.availability.available,
            "Europe is likewise a paid-location group — unavailable to the free account"
        );
        assert_eq!(europe.availability.reason.as_deref(), Some("entitlement"));

        // The paid account keeps asia available.
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::paid()));
        // Prime the network-free cache (the listing reads the CACHED
        // snapshot — round 4's contract).
        drop(engine.resolve(&country("CH"), &modifiers()));
        let catalog = engine.groups_catalog().expect("the registry serves");
        let asia = catalog
            .groups
            .iter()
            .find(|group| group.id == "protonwire:fastest-asia")
            .unwrap();
        assert!(asia.availability.available);
    }

    /// `group show` rides the same availability seam: the paid-location
    /// group's summary carries the account-tier reason under a free
    /// account.
    #[test]
    fn free_account_group_show_carries_the_tier_reason() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::free()));
        // Prime the cached snapshot (the network-free listing's source).
        drop(engine.resolve(&country("CH"), &modifiers()));
        let details = engine
            .group_details("protonwire:fastest-asia")
            .expect("the group stays visible (FR-23S)");
        assert!(!details.summary.availability.available);
        assert_eq!(
            details.summary.availability.reason.as_deref(),
            Some("entitlement")
        );
    }

    /// FR-23Q end to end: the country-excluding group refuses without
    /// a source, composes the config source, and the explicit request
    /// outranks it — with the winning source visible in the result.
    #[test]
    fn physical_country_sources_compose_fr23q() {
        // No source anywhere: the typed refusal (never a connect
        // without the exclusion).
        let engine = default_engine();
        let error = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "proton:fastest-excluding-my-country".into(),
                },
                &modifiers(),
            )
            .expect_err("no source must refuse");
        assert_eq!(error.code, RpcErrorCode::InvalidParams);
        assert!(
            error.message.contains("physical-country-required"),
            "the FR-23Q token: {error}"
        );

        // The config source: the group selects, excluding GB.
        let mut config = SystemConfig::default();
        config.connection_groups.physical_country = Some("GB".into());
        let engine = engine_over(config, 1_000_000, never_answers);
        let result = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "proton:fastest-excluding-my-country".into(),
                },
                &modifiers(),
            )
            .expect("the config source composes");
        assert_ne!(
            result.winner.exit_country, "GB",
            "the physical country is excluded"
        );
        assert_eq!(
            result.physical_country.as_ref().map(|pc| pc.source),
            Some(PhysicalCountrySource::Config)
        );
        assert_eq!(
            result
                .physical_country
                .as_ref()
                .map(|pc| pc.country.as_str()),
            Some("GB")
        );
        assert!(result.catalog.group_catalog_revision.is_some());
        assert!(result.group.is_some());

        // The explicit request outranks the config (FR-23Q's order).
        let mut config = SystemConfig::default();
        config.connection_groups.physical_country = Some("CH".into());
        let engine = engine_over(config, 1_000_000, never_answers);
        let result = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "proton:fastest-excluding-my-country".into(),
                },
                &SelectionModifiers {
                    physical_country: Some("GB".into()),
                    ..modifiers()
                },
            )
            .expect("the explicit source wins");
        assert_eq!(
            result.physical_country.as_ref().map(|pc| pc.source),
            Some(PhysicalCountrySource::ExplicitRequest)
        );
        assert_ne!(result.winner.exit_country, "GB");

        // The third source: with no explicit and no config value, the
        // CACHED Muon location serves (read-only — this request never
        // fetches, FR-23R) and reports its provenance.
        let engine = engine_with_location(SystemConfig::default(), "GB");
        let result = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "proton:fastest-excluding-my-country".into(),
                },
                &modifiers(),
            )
            .expect("the cached location composes");
        assert_eq!(
            result.physical_country.as_ref().map(|pc| pc.source),
            Some(PhysicalCountrySource::CachedLocation)
        );
        assert_ne!(result.winner.exit_country, "GB");
    }

    /// Codex PR-9 (P1, the group arm ~551): the parsed selection
    /// modifiers must MERGE into the group-resolved request — pre-fix
    /// `resolved.request` was used unchanged and `--exclude-country`
    /// was silently dropped (the result even echoed it). The
    /// discriminating shape on this fixture excludes GB (the
    /// pre-fix winner); CH never wins pre-fix, so the literal
    /// `--exclude-country CH` shape is covered by the same union.
    #[test]
    fn group_selection_honors_excluded_country_modifiers() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::paid()));
        let result = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "protonwire:fastest-europe".into(),
                },
                &SelectionModifiers {
                    excluded_countries: vec!["GB".into()],
                    ..modifiers()
                },
            )
            .expect("the exclusion constrains the group");
        assert_ne!(
            result.winner.exit_country, "GB",
            "the user exclusion eliminates every GB member"
        );
        assert_eq!(result.winner.exit_country, "CH");
    }

    /// The same merge for the `--require` family: a required feature
    /// constrains a group selection exactly as it constrains a direct
    /// one (pre-fix the modifier was dropped and GB#1 won).
    #[test]
    fn group_selection_honors_required_feature_modifiers() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::paid()));
        let result = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "protonwire:fastest-europe".into(),
                },
                &SelectionModifiers {
                    required_features: vec![SelectionFeature::P2p],
                    ..modifiers()
                },
            )
            .expect("the feature constrains the group");
        assert_eq!(
            result.winner.name, "GB-P2P",
            "the only p2p-bit member of the fixture's Europe"
        );
        assert_eq!(result.requested_features, vec!["p2p".to_owned()]);
    }

    /// The protocol precedence (FR-23P): a group's DECLARED protocol
    /// override is its official semantics — a conflicting user
    /// protocol refuses typed naming both, never a silent drop of
    /// either side (pre-fix the user's value was ignored and the
    /// selection proceeded under the group's stealth).
    #[test]
    fn group_protocol_modifier_conflicts_with_a_declared_override() {
        let engine = default_engine();
        let error = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "proton:anti-censorship".into(),
                },
                &SelectionModifiers {
                    physical_country: Some("GB".into()),
                    required_protocol: Some(SelectionProtocol::WireguardUdp),
                    ..modifiers()
                },
            )
            .expect_err("a conflicting protocol must refuse");
        assert_eq!(error.code, RpcErrorCode::InvalidParams);
        assert!(
            error.message.contains("stealth"),
            "the declared override is named: {error}"
        );
        assert!(
            error.message.contains("wireguard-udp"),
            "the requested protocol is named: {error}"
        );

        // The agreeing arm: a user protocol matching the declared
        // override is NOT a conflict — the request proceeds under the
        // group's stealth. The fixture's physicals expose WireGuard-UDP
        // only, so "proceeds" is observable as the protocol-COMPATIBILITY
        // elimination (the merged constraint evaluating against the
        // catalog), never a merge refusal.
        let agreed = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "proton:anti-censorship".into(),
                },
                &SelectionModifiers {
                    physical_country: Some("GB".into()),
                    required_protocol: Some(SelectionProtocol::Stealth),
                    ..modifiers()
                },
            )
            .expect_err("the fixture exposes no TLS endpoint");
        assert_eq!(agreed.code, RpcErrorCode::NoEligibleServer);
        let details = agreed.details.expect("FR-22 rides details");
        assert!(
            details["stages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|stage| stage["stage"] == "protocol-compatibility"),
            "the agreeing pair reaches the protocol stage, not a refusal: {details}"
        );
    }

    /// With no declared override, the user's protocol applies to the
    /// group selection (pre-fix it was dropped and the fixture's
    /// GB#1 — a WireGuard-UDP-only server — won under a stealth
    /// request).
    #[test]
    fn group_selection_honors_the_protocol_modifier_without_an_override() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::paid()));
        let error = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "protonwire:fastest-europe".into(),
                },
                &SelectionModifiers {
                    required_protocol: Some(SelectionProtocol::Stealth),
                    ..modifiers()
                },
            )
            .expect_err("the fixture exposes no TLS endpoint");
        assert_eq!(error.code, RpcErrorCode::NoEligibleServer);
        let details = error.details.expect("FR-22 rides details");
        assert!(
            details["stages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|stage| stage["stage"] == "protocol-compatibility"),
            "the eliminating stage is the protocol stage: {details}"
        );
    }

    /// The registry discipline end to end (T-33): a proton:* group
    /// refuses a ranking override; a regional group honors its
    /// declared override with DeclaredOverride provenance.
    #[test]
    fn group_selection_rides_the_registry_discipline() {
        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::paid()));
        let error = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "proton:fastest-country".into(),
                },
                &SelectionModifiers {
                    by: Some("load".into()),
                    ..modifiers()
                },
            )
            .expect_err("official groups refuse overrides");
        assert_eq!(error.code, RpcErrorCode::InvalidParams);
        assert!(
            error.message.contains("FR-23P"),
            "the discipline's rule: {error}"
        );

        let result = engine
            .resolve(
                &ConnectTarget::Group {
                    group_id: "protonwire:fastest-asia".into(),
                },
                &SelectionModifiers {
                    by: Some("load".into()),
                    ..modifiers()
                },
            )
            .expect("the declared override applies");
        assert_eq!(
            result.group.as_ref().unwrap().policy_provenance,
            "declared-override"
        );
        assert_eq!(result.selector.policy, "load");
        assert_eq!(result.winner.exit_country, "JP", "Asia's only member");
    }

    /// The forbidden throughput signal refuses typed at THIS input
    /// schema too (T-1's every-input-schema clause, the daemon arm).
    #[test]
    fn speed_ranking_refuses_typed_at_the_daemon() {
        let engine = default_engine();
        for mode in ["speed", "estimated-throughput"] {
            let error = engine
                .resolve(
                    &country("GB"),
                    &SelectionModifiers {
                        by: Some(mode.into()),
                        ..modifiers()
                    },
                )
                .expect_err("forbidden signals refuse");
            assert_eq!(error.code, RpcErrorCode::InvalidParams);
            assert!(
                error.message.contains("FR-19"),
                "`{mode}` cites the rule: {error}"
            );
        }
    }

    /// The exact-target no-fallback and the FR-22 report on the wire:
    /// an unsatisfiable request's refusal carries the structured
    /// elimination report in `details`.
    #[test]
    fn unsatisfiable_requests_carry_the_structured_report() {
        let engine = default_engine();
        let error = engine
            .resolve(
                &country("GB"),
                &SelectionModifiers {
                    excluded_countries: vec!["GB".into()],
                    ..modifiers()
                },
            )
            .expect_err("the exclusion removes both GB servers");
        assert_eq!(error.code, RpcErrorCode::NoEligibleServer);
        let details = error.details.expect("FR-22 rides details");
        assert_eq!(details["considered"], 6);
        let excluded = details["stages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|stage| stage["stage"] == "excluded-country")
            .expect("the eliminating stage is named");
        assert_eq!(
            excluded["eliminated"], 3,
            "every GB logical (both standards and the P2P server)"
        );
    }

    /// The WRITE-BACK CONTRACT (the PR-3 review's track item): a
    /// latency-ranked select probes the shortlist, and UNANSWERED
    /// attempts still advance `last_attempt_ms` — the hammering guard
    /// then skips re-probing inside the rate window.
    #[test]
    fn latency_probes_write_back_last_attempt_even_when_unanswered() {
        let engine = engine_over(SystemConfig::default(), 1_000_000, never_answers);

        // The first latency select: nothing answers, so the ranking
        // refuses on its data requirement (never fabricated).
        let error = engine
            .resolve(
                &country("GB"),
                &SelectionModifiers {
                    by: Some("latency".into()),
                    ..modifiers()
                },
            )
            .expect_err("no observations exist");
        assert_eq!(error.code, RpcErrorCode::NoEligibleServer);
        assert!(
            error.message.contains("latency data unavailable"),
            "{error}"
        );

        // THE contract: both probed endpoints carry the attempt clock
        // (unanswered ≠ unattempted), and no observation was invented.
        let state = engine.probe_state();
        assert_eq!(
            state
                .get("id-GB#1")
                .map(|endpoint| endpoint.last_attempt_ms),
            Some(1_000_000),
            "the unanswered GB#1 attempt must advance the clock"
        );
        assert_eq!(
            state
                .get("id-GB#2")
                .map(|endpoint| endpoint.last_attempt_ms),
            Some(1_000_000),
            "the unanswered GB#2 attempt must advance the clock"
        );
        assert!(
            state
                .values()
                .all(|endpoint| endpoint.observation.is_none()),
            "no observation was fabricated for an unanswered probe"
        );

        // The guard engages: inside the 60s window the planner refuses
        // another attempt for these endpoints.
        let decisions = plan_run(
            &["id-GB#1".to_owned(), "id-GB#2".to_owned()],
            &state,
            &engine.probe_budget(),
            1_000_000 + 10_000,
        );
        assert_eq!(decisions["id-GB#1"], ProbeDecision::RateLimited);
        assert_eq!(decisions["id-GB#2"], ProbeDecision::RateLimited);
    }

    /// Codex PR-9 (P1, the daemon's probe round): serial probing under
    /// the defaults (20 candidates × 750 ms) runs ≈15 s against the
    /// 10 s IPC request deadline — `--by latency` then answered with
    /// the TRANSPORT timeout instead of a selection. The round now
    /// carries a TOTAL wall-clock deadline
    /// (`latency_probe.round_deadline_ms`, default 8 s): probing stops
    /// when it passes, the answered prefix survives, and the unprobed
    /// fall to the FR-18 boundary — here the honest data-unavailable
    /// refusal, returned WITHIN the deadline, never the RPC timeout.
    #[test]
    fn the_probe_round_finishes_within_its_deadline_not_the_rpc_timeout() {
        fn stalls(_addr: SocketAddr, timeout: Duration) -> Option<Duration> {
            // The worst case the deadline must bound: every connect
            // runs out its full timeout unanswered.
            std::thread::sleep(timeout);
            None
        }
        // Five survivors under `fastest` (the SC route is server-type
        // eliminated), each stalling 400 ms: the pre-fix serial round
        // spends 5 × 400 = 2 s; the deadline is 500 ms (the production
        // arithmetic is 20 × 750 = 15 s vs the 10 s RPC deadline —
        // same shape, smaller numbers).
        let mut config = SystemConfig::default();
        config.server_selection.latency_probe.timeout_ms = 400;
        config.server_selection.latency_probe.round_deadline_ms = 500;
        let engine = engine_over(config, 1_000_000, stalls as fn(_, _) -> _);

        let start = Instant::now();
        let error = engine
            .resolve(
                &ConnectTarget::Fastest,
                &SelectionModifiers {
                    by: Some("latency".into()),
                    ..modifiers()
                },
            )
            .expect_err("nothing answers inside the deadline");
        let elapsed = start.elapsed();
        assert_eq!(error.code, RpcErrorCode::NoEligibleServer);
        assert!(
            error.message.contains("latency data unavailable"),
            "the honest data refusal, never a fabricated ordering: {error}"
        );
        assert!(
            elapsed < Duration::from_millis(1200),
            "the round returns within its deadline (measured {elapsed:?}; the pre-fix serial \
             round spent the full shortlist serially)"
        );
    }

    /// Codex PR-9 (P1, the probe round ~410): the table was cloned and
    /// the lock released BEFORE planning/execution, with the attempt
    /// clock advancing only at the write-back — two concurrent rounds
    /// could both see the same endpoints eligible and DOUBLE-proBE
    /// them, bypassing the per-endpoint interval and the global bound.
    /// The reservation protocol plans AND advances `last_attempt_ms`
    /// under one lock hold, before execution; the write-back then
    /// records only observations. Asserted via the connect seam's call
    /// count: exactly one probe per endpoint across both rounds.
    #[test]
    fn concurrent_rounds_never_double_probe_the_same_endpoint() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let parked_once = Arc::new(AtomicBool::new(false));
        // Forces the pre-fix interleaving deterministically: the FIRST
        // connect call parks until a second thread reaches the seam —
        // proof that thread planned probes over the pre-reservation
        // state — or 300 ms (the green case: the second round plans
        // nothing and never reaches the seam).
        let engine = {
            let calls = calls.clone();
            let parked_once = parked_once.clone();
            engine_over(
                SystemConfig::default(),
                1_000_000,
                move |_addr, _timeout| {
                    let mine = calls.fetch_add(1, Ordering::SeqCst);
                    if !parked_once.swap(true, Ordering::SeqCst) {
                        let deadline = Instant::now() + Duration::from_millis(300);
                        while calls.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                    }
                    let _ = mine;
                    Some(Duration::from_millis(25))
                },
            )
        };

        // `country GB` shortlists exactly the three GB logicals.
        let target = country("GB");
        let mods = SelectionModifiers {
            by: Some("latency".into()),
            ..modifiers()
        };
        std::thread::scope(|scope| {
            scope.spawn(|| engine.resolve(&target, &mods));
            scope.spawn(|| engine.resolve(&target, &mods));
        });

        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "each of the three GB endpoints is probed exactly ONCE across both concurrent \
             rounds — the reservation holds the per-endpoint interval and the global bound \
             across sessions (pre-fix: 6, both rounds probing the full shortlist)"
        );
        // And the probe table shows it: every GB endpoint carries the
        // reserved attempt clock.
        let state = engine.probe_state();
        for endpoint in ["id-GB#1", "id-GB#2", "id-GB-P2P"] {
            assert_eq!(
                state.get(endpoint).map(|entry| entry.last_attempt_ms),
                Some(1_000_000),
                "`{endpoint}` carries the reserved attempt clock"
            );
        }
    }

    /// The verdict round's GAP-2: the daemon's `max_candidates` cap
    /// bounds the shortlist BEFORE the executor resolves addresses —
    /// what the planner's own per-run cap cannot bound (address
    /// resolution is O(catalog) per id). A fixture exceeding the cap
    /// must probe at most `max_candidates` endpoints, never every
    /// survivor. Mutation: delete the `.take(cap)` and this fails.
    #[test]
    fn the_latency_shortlist_is_capped_at_max_candidates() {
        fn answers(_addr: SocketAddr, _timeout: Duration) -> Option<Duration> {
            Some(Duration::from_millis(25))
        }
        // All six logicals survive a bare regional target (every
        // country is a member of some region only under regional
        // groups; a `fastest` target matches all six).
        let mut config = SystemConfig::default();
        config.server_selection.latency_probe.max_candidates = 3;
        let engine = engine_over(config, 1_000_000, answers as fn(_, _) -> _);

        let result = engine
            .resolve(
                &ConnectTarget::Fastest,
                &SelectionModifiers {
                    by: Some("latency".into()),
                    ..modifiers()
                },
            )
            .expect("the probed shortlist serves the ranking");
        // The unprobed survivors eliminated at the FR-18 shortlist
        // boundary (no-latency-observation) — the CONTRACT here is the
        // probe-state population: at most `max_candidates` (3)
        // endpoints carry an attempt clock, never all six survivors.
        assert_eq!(result.hard_filters.survivors, 3);
        let attempted = engine
            .probe_state()
            .values()
            .filter(|endpoint| endpoint.last_attempt_ms > 0)
            .count();
        assert_eq!(
            attempted, 3,
            "the shortlist cap bounds the probed population, not the survivor count"
        );
    }

    /// The answered arm: fresh observations serve the ranking, ride
    /// the winner's signals as `probe-observed`, and are REUSED
    /// without re-probing inside the reuse window.
    #[test]
    fn answered_probes_rank_and_are_reused_inside_the_window() {
        fn answers(_addr: SocketAddr, _timeout: Duration) -> Option<Duration> {
            Some(Duration::from_millis(25))
        }
        let engine = engine_over(SystemConfig::default(), 1_000_000, answers as fn(_, _) -> _);
        let result = engine
            .resolve(
                &country("GB"),
                &SelectionModifiers {
                    by: Some("latency".into()),
                    ..modifiers()
                },
            )
            .expect("the answered probes rank");
        assert_eq!(result.winner.signals.provenance, "probe-observed");
        assert_eq!(result.winner.signals.latency_ms, Some(25));
        assert_eq!(
            result.hard_filters.survivors, 3,
            "every GB candidate was probed and ranked"
        );

        // The reuse window: at +10s the planner REUSES, never re-probes.
        let state = engine.probe_state();
        assert!(
            state
                .values()
                .all(|endpoint| endpoint.observation.is_some())
        );
        let decisions = plan_run(
            &["id-GB#1".to_owned(), "id-GB#2".to_owned()],
            &state,
            &engine.probe_budget(),
            1_000_000 + 10_000,
        );
        assert!(matches!(decisions["id-GB#1"], ProbeDecision::Reuse(_)));
    }

    /// ICMP fail-closed (FR-19B): the opted-in transport observes
    /// nothing (the raw-socket executor is deliberately unwired;
    /// CAP_NET_RAW is never assumed), so the latency ranking refuses
    /// on its data requirement — never a fabricated RTT.
    #[test]
    fn icmp_transport_fails_closed() {
        fn answers(_addr: SocketAddr, _timeout: Duration) -> Option<Duration> {
            panic!("the icmp arm must never reach the TCP connect seam")
        }
        let mut config = SystemConfig::default();
        config.server_selection.latency_probe.transport = ProbeTransport::Icmp;
        let engine = engine_over(config, 1_000_000, answers as fn(_, _) -> _);
        let error = engine
            .resolve(
                &country("GB"),
                &SelectionModifiers {
                    by: Some("latency".into()),
                    ..modifiers()
                },
            )
            .expect_err("the icmp arm observes nothing");
        assert_eq!(error.code, RpcErrorCode::NoEligibleServer);
        assert!(
            error.message.contains("latency data unavailable"),
            "{error}"
        );
    }

    /// The registry-served catalog (FR-23I/U/S): the full 14 groups,
    /// the revision stamps, and per-group availability — the
    /// country-excluding group reports physical-country-required, the
    /// regional groups are available (or no-eligible-server where the
    /// fixture has no members), and nothing here performs a network
    /// request.
    #[test]
    fn groups_catalog_serves_the_registry_with_availability() {
        let engine = default_engine();
        let catalog = engine.groups_catalog().expect("the registry serves");
        assert_eq!(catalog.groups.len(), 14, "the canonical registry");
        assert!(!catalog.catalog_revision.is_empty());
        assert!(!catalog.taxonomy_revision.is_empty());

        let excluding = catalog
            .groups
            .iter()
            .find(|group| group.id == "proton:fastest-excluding-my-country")
            .unwrap();
        assert!(!excluding.availability.available);
        assert_eq!(
            excluding.availability.reason.as_deref(),
            Some("physical-country-required")
        );

        let asia = catalog
            .groups
            .iter()
            .find(|group| group.id == "protonwire:fastest-asia")
            .unwrap();
        // The regional group is GROUP-LEVEL entitlement-gated (round 6):
        // no cached snapshot on this engine → composition-missing, never
        // a false available — even though the fixture's JP#1 is a
        // tier-0 member.
        assert!(
            !asia.availability.available,
            "the regional group is entitlement-gated (no snapshot composed on this engine)"
        );
        assert_eq!(
            asia.availability.reason.as_deref(),
            Some("entitlement-composition-missing")
        );

        // GB/CH/SE are European, but Europe is a PaidLocationSelection
        // regional group under the round-6 gate: with no snapshot
        // composed on this engine it reports composition-missing (never
        // a false available); South America has no member at all.
        let europe = catalog
            .groups
            .iter()
            .find(|group| group.id == "protonwire:fastest-europe")
            .unwrap();
        assert!(!europe.availability.available);
        assert_eq!(
            europe.availability.reason.as_deref(),
            Some("entitlement-composition-missing")
        );
        let south_america = catalog
            .groups
            .iter()
            .find(|group| group.id == "protonwire:fastest-south-america")
            .unwrap();
        assert!(!south_america.availability.available);
        assert_eq!(
            south_america.availability.reason.as_deref(),
            Some("entitlement-composition-missing"),
            "the regional gate precedes the member check (no snapshot on this engine)"
        );
    }

    /// `group show`: the full definition for a known id; the typed
    /// refusal for an unknown one.
    #[test]
    fn group_show_serves_definitions_and_refuses_unknown_ids() {
        let engine = default_engine();
        let details = engine
            .group_details("proton:max-security")
            .expect("the routed group details");
        assert_eq!(details.summary.id, "proton:max-security");
        assert_eq!(details.target, "secure-core");
        assert_eq!(details.target_detail.as_deref(), Some("fastest->fastest"));
        assert!(details.immutable);
        assert!(!details.sources.is_empty());

        let error = engine
            .group_details("proton:nonexistent")
            .expect_err("unknown ids refuse");
        assert_eq!(error.code, RpcErrorCode::InvalidParams);
        assert!(error.message.contains("unknown group"));
    }

    /// The group-catalog availability names no-catalog when nothing is
    /// cached (FR-23S: the group stays VISIBLE with its reason).
    #[test]
    fn groups_without_a_catalog_report_no_catalog() {
        let engine = engine_without_catalog();
        let catalog = engine.groups_catalog().expect("the registry still serves");
        assert_eq!(catalog.groups.len(), 14, "FR-23S: visibility survives");
        assert!(
            catalog
                .groups
                .iter()
                .all(|group| !group.availability.available)
        );
        assert!(
            catalog
                .groups
                .iter()
                .all(|group| group.availability.reason.as_deref() == Some("no-catalog"))
        );
    }

    /// The balanced composition (P2-2) through the daemon: the
    /// config's weights reach the ranking (a load-only weight set
    /// picks the lowest-load GB server, inverting the score order).
    #[test]
    fn balanced_composes_the_configured_weights() {
        let mut config = SystemConfig::default();
        config.server_selection.balanced_weights.load = 1.0;
        config.server_selection.balanced_weights.latency = 0.0;
        config.server_selection.balanced_weights.stability = 0.0;
        config.server_selection.balanced_weights.feature_match = 0.0;
        let engine = engine_over(config, 1_000_000, never_answers);
        let result = engine
            .resolve(
                &country("GB"),
                &SelectionModifiers {
                    by: Some("balanced".into()),
                    ..modifiers()
                },
            )
            .expect("the config weights rank");
        assert_eq!(
            result.winner.name, "GB-P2P",
            "load 10 beats 20 and 80 under a load-only weight set"
        );
        let weighted = result
            .winner
            .signals
            .weighted
            .expect("balanced carries the breakdown");
        assert_eq!(result.winner.signals.provenance, "weighted-breakdown");
        assert!(weighted.load_term > 0.0);
        assert_eq!(
            weighted.latency_term, 0.0,
            "the config zeroed the latency weight"
        );
    }

    /// The random policy draws on OS entropy through the daemon
    /// (RandomEntropyRequired is unreachable here) and the special
    /// classes map onto the feature constraints (p2p selects the P2P
    /// server — under a PAID plan: the round-8 capability gate makes
    /// the special classes entitlement-carried).
    #[test]
    fn random_draws_os_entropy_and_specials_map_to_features() {
        let engine = default_engine();
        let result = engine
            .resolve(&ConnectTarget::Random, &modifiers())
            .expect("the daemon supplies entropy");
        assert_eq!(result.selector.policy, "random");
        assert!(result.winner.signals.proton_score.is_some());

        let engine = default_engine();
        engine
            .entitlement()
            .install(Arc::new(FakeEntitlements::paid()));
        let p2p = engine
            .resolve(
                &ConnectTarget::Special {
                    class: SpecialClass::P2p,
                },
                &modifiers(),
            )
            .expect("the p2p class selects under a paid plan");
        assert_eq!(p2p.winner.name, "GB-P2P", "the feature bit filtered");
        assert_eq!(p2p.selector.target, "p2p");
    }

    /// An adapter whose fetch NEVER lands (the worker parks in a
    /// loop): isolates the WAITER-side timing from the worker side —
    /// the deadline-clamp tests measure when the waiter gives up,
    /// never when an answer arrives.
    struct NeverLandingEntitlements;

    impl EntitlementsApi for NeverLandingEntitlements {
        fn fetch(
            &self,
        ) -> Result<
            protonwire_api::entitlements::VpnEntitlements,
            protonwire_api::entitlements::EntitlementsError,
        > {
            loop {
                std::thread::park();
            }
        }
    }

    /// A scripted entitlements adapter over the recorded contract's
    /// shape (paid: MaxTier 3; free: MaxTier 0).
    struct FakeEntitlements {
        body: &'static str,
    }

    impl FakeEntitlements {
        fn paid() -> Self {
            Self {
                body: r#"{
                    "Code": 1000, "Error": null, "Details": null,
                    "Subscribed": 1, "Services": 4, "Delinquent": 0, "Credit": 0,
                    "HasPaymentMethod": 1,
                    "VPN": {
                        "Status": 1, "ExpirationTime": 1820000000,
                        "PlanName": "visionary2028", "PlanTitle": "Visionary",
                        "MaxTier": 3, "MaxConnect": 10, "Name": "synthetic",
                        "GroupID": null, "IsBusiness": false,
                        "NetShield": { "Malware": true, "AdsAndTrackers": true, "AdultContent": false }
                    }
                }"#,
            }
        }

        fn free() -> Self {
            Self {
                body: r#"{
                    "Code": 1000, "Error": null, "Details": null,
                    "Subscribed": 0, "Services": 1, "Delinquent": 0, "Credit": 0,
                    "HasPaymentMethod": 0,
                    "VPN": {
                        "Status": 1, "ExpirationTime": 1820000000,
                        "PlanName": "free", "PlanTitle": "Proton Free",
                        "MaxTier": 0, "MaxConnect": 1, "Name": "synthetic",
                        "GroupID": null, "IsBusiness": false, "NetShield": null
                    }
                }"#,
            }
        }
    }

    impl EntitlementsApi for FakeEntitlements {
        fn fetch(
            &self,
        ) -> Result<
            protonwire_api::entitlements::VpnEntitlements,
            protonwire_api::entitlements::EntitlementsError,
        > {
            protonwire_api::entitlements::VpnEntitlements::from_wire_bytes(self.body.as_bytes())
        }
    }
}
