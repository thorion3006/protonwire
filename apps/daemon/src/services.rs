//! The S9 daemon-side service surface: the single-flight scheduler
//! wiring, the catalog-fetch bridge, and the provider cells the session
//! lane installs its engine adapters into.
//!
//! Architecture: core owns the scheduler POLICY but must not depend on a
//! transport ([`protonwire_core::scheduler`]'s own architecture note), so
//! the daemon bridges the S6 adapter traits onto core's seams here:
//!
//! * [`CatalogService`] is the [`CatalogFetch`] closure the scheduler is
//!   constructed with — it resolves the CURRENT catalog adapter from a
//!   provider cell and maps the adapter result onto core's
//!   [`FetchOutcome`]/[`FetchFailure`], carrying [`ApiError::RateLimited`]
//!   onto [`FetchFailure::RateLimited`] so the scheduler's suppression
//!   path is live (S9 obligation b — until this bridge existed, no
//!   rate-limited fetch could ever mint a suppression deadline).
//! * [`DaemonServices::build`] constructs the production scheduler
//!   STRICTLY ([`Scheduler::production`], trust root `/`): a malformed,
//!   oversized, or fs-trust-refused persisted document ABORTS startup —
//!   never a default fallback, which would re-arm the FR-13H refetch
//!   storm the persisted high-water mark exists to prevent.

use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;

use protonwire_api::{ApiError, AuthenticationApi, CatalogApi, CatalogFetch, LoginStatus};
use protonwire_core::scheduler::CatalogFetch as SchedulerFetch;
use protonwire_core::scheduler::{
    FetchFailure, FetchOutcome, Scheduler, SchedulerConfig, SchedulerError, SystemClock,
};
use protonwire_frontend_api::ServersRefreshOutcome;
use protonwire_frontend_api::ServersRefreshReport;
use protonwire_store::catalog::CatalogCache;
use protonwire_store::catalog::CatalogCacheError;
use protonwire_store::config::SystemConfig;
use protonwire_store::paths::ConfigPaths;

/// The catalog-adapter provider cell: the session lane INSTALLS the
/// live `&dyn CatalogApi` (a `MuonCatalog` over the authenticated
/// session) once the engine wiring lands; until then every fetch
/// refuses with a typed transport failure — never a fabricated catalog
/// and never a silent success.
#[derive(Default)]
pub struct CatalogService {
    provider: RwLock<Option<Arc<dyn CatalogApi>>>,
}

impl CatalogService {
    /// Installs (or replaces) the catalog adapter.
    pub fn install(&self, api: Arc<dyn CatalogApi>) {
        *self.provider.write().expect("catalog provider lock") = Some(api);
    }

    /// One scheduler-seam fetch through the current adapter, bridged.
    pub fn fetch(&self, etag: Option<&str>) -> Result<FetchOutcome, FetchFailure> {
        let guard = self.provider.read().expect("catalog provider lock");
        match guard.as_ref() {
            Some(api) => bridge_fetch(api.fetch(etag)),
            None => Err(FetchFailure::Transport(
                "no catalog adapter installed (the session engine wiring owns this slot)"
                    .to_owned(),
            )),
        }
    }

    /// The [`SchedulerFetch`] closure over a shared service.
    pub fn closure(self: &Arc<Self>) -> SchedulerFetch {
        let service = Arc::clone(self);
        Arc::new(move |etag| service.fetch(etag))
    }
}

/// The authentication-adapter provider cell (the login family's twin of
/// [`CatalogService`]): the session lane INSTALLS the live
/// `&dyn AuthenticationApi` once the engine wiring lands. An empty cell
/// is answered by the handler with a typed NotImplemented — never a
/// fabricated login state.
#[derive(Default)]
pub struct AuthProvider {
    auth: RwLock<Option<Arc<dyn AuthenticationApi>>>,
}

impl AuthProvider {
    /// Installs (or replaces) the authentication adapter.
    pub fn install(&self, api: Arc<dyn AuthenticationApi>) {
        *self.auth.write().expect("auth provider lock") = Some(api);
    }

    /// The current adapter, if the session lane has installed one.
    pub fn current(&self) -> Option<Arc<dyn AuthenticationApi>> {
        self.auth.read().expect("auth provider lock").clone()
    }
}

/// S9 obligation (c): the begin_login InvalidState guard, implemented as
/// the daemon-side precondition CALL SEQUENCE (the work order's
/// mandated shape — `auth.rs` belongs to the api lane): before any
/// credentials reach the wire, the daemon consults the adapter's login
/// status and refuses every non-logged-out state with
/// [`ApiError::InvalidState`] — an existing session (LoggedIn) and a
/// session-needing-refresh OR a store-visible pending second-factor
/// challenge (NeedsRefresh; MuonAuth parks the partial auth in its
/// store at the 2FA step, which is what makes the pending challenge
/// observable here at all).
///
/// API-LANE FINDING (recorded for that lane, not fixed here): the guard
/// ultimately belongs INSIDE `MuonAuth::begin_login` — the adapter owns
/// its `pending` field directly and could refuse the store-invisible
/// window precisely, whereas this sequence can only observe what
/// `login_status()` reports. Until the adapter-side guard lands, this
/// sequence is the fail-closed front door the BeginLogin handler calls.
pub fn begin_login_guarded(
    auth: &dyn AuthenticationApi,
    username: &str,
    password: &str,
) -> Result<protonwire_api::LoginStep, ApiError> {
    // The precondition call sequence: refuse every non-logged-out
    // status BEFORE the credentials cross the wire (the client
    // surfaces orchestrate the order — logout or complete the flow
    // first).
    match auth.login_status()? {
        LoginStatus::LoggedOut => auth.begin_login(username, password),
        LoginStatus::LoggedIn => Err(ApiError::InvalidState(
            "a session already exists; log out before beginning a new login",
        )),
        LoginStatus::NeedsRefresh => Err(ApiError::InvalidState(
            "a session or pending second-factor challenge already exists; \
             refresh it, complete the challenge, or log out first",
        )),
    }
}

/// Maps an adapter error onto the wire taxonomy. `InvalidState` maps
/// onto `RpcErrorCode::InvalidParams` — the wire decision the
/// `BeginLogin` doc records ("invalid state semantics"); the login
/// family's other adapter refusals map onto their S2 codes, transport
/// onto NetworkUnavailable (PRD 9.8 (6)).
pub fn api_error_to_rpc(error: ApiError) -> protonwire_frontend_api::RpcError {
    use protonwire_frontend_api::RpcError;
    use protonwire_frontend_api::RpcErrorCode;
    match error {
        ApiError::BlockedUpstream(reason) => RpcError::new(
            RpcErrorCode::UpstreamCapabilityBlocked,
            format!("blocked upstream: {reason}"),
        ),
        ApiError::UnsupportedChallenge(reason) => RpcError::new(
            RpcErrorCode::UnsupportedChallenge,
            format!("unsupported challenge: {reason}"),
        ),
        ApiError::InvalidState(reason) => RpcError::new(
            RpcErrorCode::InvalidParams,
            format!("invalid state: {reason}"),
        ),
        ApiError::RateLimited { .. } => {
            RpcError::new(RpcErrorCode::RateLimited, "rate limited by the upstream")
        }
        ApiError::Transport(detail) => RpcError::new(RpcErrorCode::NetworkUnavailable, detail),
    }
}

/// Maps one adapter login step onto the wire outcome (the shapes are
/// parallel by design; the wire carries no secrets).
pub fn login_step_to_wire(
    step: protonwire_api::LoginStep,
) -> protonwire_frontend_api::LoginOutcome {
    use protonwire_frontend_api::LoginOutcome;
    match step {
        protonwire_api::LoginStep::Session(info) => LoginOutcome::Session {
            user_id: info.user_id,
            session_id: info.session_id,
        },
        protonwire_api::LoginStep::Challenge(challenge) => LoginOutcome::Challenge {
            totp_enabled: challenge.totp_enabled,
            fido2: challenge
                .fido2
                .map(|fido2| protonwire_frontend_api::Fido2ChallengeParams {
                    challenge: fido2.challenge,
                    allow_credentials: fido2.allow_credentials,
                }),
        },
        protonwire_api::LoginStep::Blocked(reason) => LoginOutcome::Blocked {
            reason: match reason {
                protonwire_api::BlockedReason::HumanVerification => {
                    protonwire_frontend_api::LoginBlockedReason::HumanVerification
                }
                protonwire_api::BlockedReason::OrganizationSso => {
                    protonwire_frontend_api::LoginBlockedReason::OrganizationSso
                }
                protonwire_api::BlockedReason::GuestLogin => {
                    protonwire_frontend_api::LoginBlockedReason::GuestLogin
                }
                protonwire_api::BlockedReason::Feedback => {
                    protonwire_frontend_api::LoginBlockedReason::Feedback
                }
                protonwire_api::BlockedReason::UnsupportedChallenge => {
                    protonwire_frontend_api::LoginBlockedReason::UnsupportedChallenge
                }
            },
        },
    }
}

/// Maps the adapter login status onto the wire status (parallel
/// vocabularies).
pub fn login_status_to_wire(status: LoginStatus) -> protonwire_frontend_api::SessionStatus {
    match status {
        LoginStatus::LoggedOut => protonwire_frontend_api::SessionStatus::LoggedOut,
        LoginStatus::LoggedIn => protonwire_frontend_api::SessionStatus::LoggedIn,
        LoginStatus::NeedsRefresh => protonwire_frontend_api::SessionStatus::NeedsRefresh,
    }
}

/// S9 obligation (b): maps one adapter fetch result onto the scheduler's
/// fetch seam. [`ApiError::RateLimited`] carries its (already-clamped at
/// the ef0074f parse seam — [`protonwire_api::catalog::
/// RETRY_AFTER_CEILING_SECONDS`], 30 days) `Retry-After` delay onto
/// [`FetchFailure::RateLimited`]; every other adapter failure is
/// transport-class; successes pass through byte-for-byte.
pub fn bridge_fetch(result: Result<CatalogFetch, ApiError>) -> Result<FetchOutcome, FetchFailure> {
    match result {
        Ok(CatalogFetch::Changed { etag, body }) => Ok(FetchOutcome::Changed { etag, body }),
        Ok(CatalogFetch::NotModified) => Ok(FetchOutcome::NotModified),
        Err(ApiError::RateLimited {
            retry_after_seconds,
        }) => Err(FetchFailure::RateLimited {
            retry_after_seconds,
        }),
        Err(other) => Err(FetchFailure::Transport(other.to_string())),
    }
}

/// Failures of the S9 service construction — every arm aborts startup
/// (exit 15, the PRD 9.8 config-class code: the persisted policy state
/// is daemon-managed configuration in the same sense as the system
/// document, and a misdeployment is a deployment error, not a runtime
/// degradation to serve through).
#[derive(Debug, thiserror::Error)]
pub enum ServiceStartupError {
    /// The scheduler could not be constructed: a sub-floor policy
    /// derivation (unreachable through a validated `SystemConfig` —
    /// defense in depth) or a STRICT load refusal of the persisted
    /// deadlines/cache documents (malformed, oversized, or
    /// fs-trust-refused).
    #[error("scheduler construction failed: {0}")]
    Scheduler(#[from] SchedulerError),
}

/// The live daemon services the request handler dispatches into.
pub struct DaemonServices {
    /// The single-flight catalog scheduler (FR-13C: one per process).
    pub scheduler: Arc<Scheduler>,
    /// The catalog adapter cell + the scheduler's fetch bridge.
    pub catalog: Arc<CatalogService>,
    /// The authentication adapter cell (the login family's provider).
    pub auth: AuthProvider,
    /// The strict-loaded catalog cache document location (the
    /// `ServersList` read side; the scheduler is the only writer).
    pub cache_file: std::path::PathBuf,
    /// The fs_trust root every strict load here walks to — `/` in
    /// production, the hermetic root in tests (the same opt-in the
    /// construction takes).
    trust_root: std::path::PathBuf,
}

impl DaemonServices {
    /// The production construction: derives the scheduler policy from
    /// the validated system configuration and constructs the scheduler
    /// STRICTLY over the `ConfigPaths` cache directory with `/` as the
    /// fs_trust root.
    ///
    /// # Errors
    /// [`ServiceStartupError::Scheduler`] — see its doc for the
    /// fail-closed contract (abort startup; never default deadlines).
    pub fn build(config: &SystemConfig, paths: &ConfigPaths) -> Result<Self, ServiceStartupError> {
        Self::build_with_trust_root(config, paths, Path::new("/"))
    }

    /// The same construction over an explicit fs_trust root — the
    /// hermetic-test opt-in (see the core-side doc on
    /// [`Scheduler::production_with_trust_root`]): an unprivileged
    /// runner cannot make a tree root-owned, so the ownership pass
    /// would refuse every test-planted document before the arm under
    /// test. Production callers use [`Self::build`] (root `/`).
    ///
    /// # Errors
    /// As [`Self::build`].
    pub fn build_with_trust_root(
        config: &SystemConfig,
        paths: &ConfigPaths,
        trust_root: &Path,
    ) -> Result<Self, ServiceStartupError> {
        let policy = SchedulerConfig::from_metadata_cache(&config.server_selection.metadata_cache)?;
        let catalog = Arc::new(CatalogService::default());
        let scheduler = Arc::new(Scheduler::production_with_trust_root(
            policy,
            Arc::new(SystemClock),
            catalog.closure(),
            paths,
            trust_root,
        )?);
        Ok(Self {
            scheduler,
            catalog,
            auth: AuthProvider::default(),
            cache_file: paths.cache_dir.join("servers.json"),
            trust_root: trust_root.to_path_buf(),
        })
    }

    /// Serves the cached catalog revision for `ServersList` (FR-10: the
    /// raw upstream body byte-for-byte, never rewritten) with the same
    /// STRICT posture the scheduler loaded it under — a cache document
    /// that changed into something untrusted since boot fails closed
    /// rather than serving possibly-planted bytes.
    ///
    /// # Errors
    /// [`CatalogCacheError`] when a PRESENT document fails the strict
    /// load (tampered, oversized, malformed). An ABSENT document is the
    /// legitimate nothing-cached-yet state and yields `Ok(None)`.
    pub fn cached_catalog(
        &self,
    ) -> Result<Option<protonwire_store::catalog::CachedCatalog>, CatalogCacheError> {
        CatalogCache::new(&self.cache_file).load_strict(&self.trust_root)
    }
}

/// Converts one scheduler refresh outcome onto the wire report
/// (`ServersRefresh`'s reply). The body bytes stay daemon-side (the wire
/// carries the etag only; clients read the catalog through
/// `ServersList`).
pub fn refresh_report_to_wire(
    report: protonwire_core::scheduler::RefreshReport,
) -> ServersRefreshReport {
    let outcome = match report.outcome {
        protonwire_core::scheduler::RefreshOutcome::Changed { etag, .. } => {
            ServersRefreshOutcome::Changed { etag }
        }
        protonwire_core::scheduler::RefreshOutcome::NotModified => {
            ServersRefreshOutcome::NotModified
        }
        protonwire_core::scheduler::RefreshOutcome::RateLimited {
            retry_after_seconds,
        } => ServersRefreshOutcome::RateLimited {
            retry_after_seconds,
        },
        protonwire_core::scheduler::RefreshOutcome::Failed { reason } => {
            ServersRefreshOutcome::Failed { reason }
        }
    };
    ServersRefreshReport {
        outcome,
        coalesced: report.coalesced,
        next_eligible_unix: report.next_eligible_unix,
        suppression_until_unix: report.suppression_until_unix,
    }
}

/// Test-support: a fake authentication adapter shared by the services
/// and handler test suites (a scripted status plus a begin_login
/// call-record — the guard's observable contract).
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;

    /// A fake authentication adapter with a scripted status that
    /// records whether `begin_login` was reached (the guard's
    /// observable contract: the precondition must refuse BEFORE any
    /// credentials reach the wire).
    pub(crate) struct FakeAuth {
        status: LoginStatus,
        begin_login_called: std::sync::atomic::AtomicBool,
    }

    impl FakeAuth {
        /// A fake reporting `status`.
        pub(crate) fn new(status: LoginStatus) -> Self {
            Self {
                status,
                begin_login_called: std::sync::atomic::AtomicBool::new(false),
            }
        }

        /// Whether `begin_login` was reached.
        pub(crate) fn begin_login_was_called(&self) -> bool {
            self.begin_login_called
                .load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl AuthenticationApi for FakeAuth {
        fn login_status(&self) -> Result<LoginStatus, ApiError> {
            Ok(self.status)
        }

        fn begin_login(
            &self,
            _username: &str,
            _password: &str,
        ) -> Result<protonwire_api::LoginStep, ApiError> {
            self.begin_login_called
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(protonwire_api::LoginStep::Session(
                protonwire_api::SessionInfo {
                    user_id: "u".to_owned(),
                    session_id: "s".to_owned(),
                },
            ))
        }

        fn submit_two_factor(&self, _code: &str) -> Result<protonwire_api::LoginStep, ApiError> {
            Err(ApiError::InvalidState("no 2FA challenge in progress"))
        }

        fn submit_fido_payload(
            &self,
            _payload: &protonwire_api::Fido2Payload,
        ) -> Result<protonwire_api::LoginStep, ApiError> {
            Err(ApiError::InvalidState("no 2FA challenge in progress"))
        }

        fn refresh(&self) -> Result<LoginStatus, ApiError> {
            Ok(self.status)
        }

        fn logout(&self) -> Result<(), ApiError> {
            Ok(())
        }

        fn fork(&self, _child_id: &str) -> Result<protonwire_api::ForkSelector, ApiError> {
            Err(ApiError::InvalidState("logged out"))
        }

        fn import_fork(
            &self,
            _selector: &protonwire_api::ForkSelector,
        ) -> Result<protonwire_api::LoginStep, ApiError> {
            Err(ApiError::InvalidState("an active session exists"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::testkit::FakeAuth;

    /// S9 (c), the named obligation: begin_login at a NON-logged-out
    /// status refuses with `ApiError::InvalidState` and NEVER reaches
    /// the adapter's `begin_login` — the credentials must not cross the
    /// wire when the flow is already occupied. Red observed against the
    /// delegate-only plumbing (the guard removed): every shape returned
    /// the fake's Ok(Session) with `begin_login_was_called()` true.
    #[test]
    fn begin_login_refuses_an_existing_session_or_pending_challenge() {
        for status in [LoginStatus::LoggedIn, LoginStatus::NeedsRefresh] {
            let fake = FakeAuth::new(status);
            let err = begin_login_guarded(&fake, "user", "pass")
                .err()
                .unwrap_or_else(|| panic!("status {status:?} must refuse"));
            assert!(
                matches!(err, ApiError::InvalidState(_)),
                "the refusal must be InvalidState for {status:?}: {err}"
            );
            assert!(
                !fake.begin_login_was_called(),
                "the precondition must refuse before any credentials reach the wire ({status:?})"
            );
        }
        // The LoggedOut control: the login proceeds through the adapter.
        let fake = FakeAuth::new(LoginStatus::LoggedOut);
        assert!(begin_login_guarded(&fake, "user", "pass").is_ok());
        assert!(fake.begin_login_was_called());
    }

    /// A fake adapter scripting one result per call. `ApiError` is not
    /// `Clone` (it owns its detail strings), so the fake produces a
    /// fresh result per call.
    struct FakeCatalog {
        produce: Box<dyn Fn() -> Result<CatalogFetch, ApiError> + Send + Sync>,
    }

    impl FakeCatalog {
        fn always(
            produce: impl Fn() -> Result<CatalogFetch, ApiError> + Send + Sync + 'static,
        ) -> Self {
            Self {
                produce: Box::new(produce),
            }
        }
    }

    impl CatalogApi for FakeCatalog {
        fn fetch(&self, _etag: Option<&str>) -> Result<CatalogFetch, ApiError> {
            (self.produce)()
        }
    }

    fn changed() -> Result<CatalogFetch, ApiError> {
        Ok(CatalogFetch::Changed {
            etag: Some("\"v1\"".to_owned()),
            body: b"catalog-bytes".to_vec(),
        })
    }

    /// S9 (b): every arm of the RateLimited→FetchFailure bridge. The
    /// `RateLimited` mapping is the obligation — the scheduler's
    /// suppression path is production-dead without it (a rate-limited
    /// fetch would degrade to a plain transport failure, minting NO
    /// suppression deadline and hammering Proton on the next window).
    #[test]
    fn bridge_maps_every_adapter_arm_onto_the_scheduler_seam() {
        // Changed passes through byte-for-byte (the scheduler validates
        // and persists the body; nothing is rewritten here).
        assert_eq!(
            bridge_fetch(changed()),
            Ok(FetchOutcome::Changed {
                etag: Some("\"v1\"".to_owned()),
                body: b"catalog-bytes".to_vec(),
            })
        );
        assert_eq!(
            bridge_fetch(Ok(CatalogFetch::NotModified)),
            Ok(FetchOutcome::NotModified)
        );
        // THE obligation: the parsed (already-clamped) Retry-After delay
        // rides onto FetchFailure::RateLimited untouched.
        assert_eq!(
            bridge_fetch(Err(ApiError::RateLimited {
                retry_after_seconds: Some(60),
            })),
            Err(FetchFailure::RateLimited {
                retry_after_seconds: Some(60),
            })
        );
        assert_eq!(
            bridge_fetch(Err(ApiError::RateLimited {
                retry_after_seconds: None,
            })),
            Err(FetchFailure::RateLimited {
                retry_after_seconds: None
            })
        );
        // Every other adapter failure degrades to transport-class (the
        // scheduler still paces from the attempt, but no suppression).
        for error in [
            ApiError::Transport("timeout".to_owned()),
            ApiError::BlockedUpstream("human-verification"),
            ApiError::UnsupportedChallenge("recovery-code"),
            ApiError::InvalidState("no 2FA challenge in progress"),
        ] {
            let mapped = bridge_fetch(Err(error));
            assert!(
                matches!(mapped, Err(FetchFailure::Transport(_))),
                "non-rate-limit failures must stay transport-class: {mapped:?}"
            );
        }
    }

    /// The provider cell: an empty cell refuses with a typed transport
    /// failure (never a fabricated catalog, never a silent success), an
    /// installed adapter serves through the bridge.
    #[test]
    fn catalog_service_refuses_without_an_installed_adapter() {
        let service = CatalogService::default();
        match service.fetch(None) {
            Err(FetchFailure::Transport(reason)) => assert!(
                reason.contains("no catalog adapter installed"),
                "the refusal must name the empty cell: {reason}"
            ),
            other => panic!("empty cell must refuse, got {other:?}"),
        }
        service.install(Arc::new(FakeCatalog::always(|| {
            Err(ApiError::RateLimited {
                retry_after_seconds: Some(7),
            })
        })));
        assert_eq!(
            service.fetch(None),
            Err(FetchFailure::RateLimited {
                retry_after_seconds: Some(7),
            })
        );
    }

    /// (a): the strict construction refuses a corrupted
    /// persisted-deadlines document — never a default fallback. Arm
    /// disclosure (the honest red-evidence nuance): unprivileged
    /// runners cannot make the planted tree root-owned, so the walk's
    /// ownership pass refuses it before the parse arm — the class is
    /// FsTrust; a root-owned tree reaches the Malformed arm (pinned at
    /// the store seam by the deadlines suite). The pinned contract is
    /// the REFUSAL, with the scheduler-error surface intact.
    #[test]
    fn build_refuses_a_corrupted_deadlines_document() {
        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-s9-build-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = ConfigPaths::rooted(&dir);
        std::fs::create_dir_all(&paths.cache_dir).unwrap();
        std::fs::write(paths.cache_dir.join("deadlines.json"), b"{not json").unwrap();

        let err = DaemonServices::build_with_trust_root(&SystemConfig::default(), &paths, &dir)
            .err()
            .expect("a corrupted deadlines document must refuse construction");
        assert!(
            matches!(err, ServiceStartupError::Scheduler(_)),
            "the refusal must surface the scheduler's strict-load failure: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// (a) control: a cache directory whose documents are all ABSENT is
    /// the legitimate first boot — the walk skips absent components
    /// (MissingLeaf::Allow semantics), the scheduler constructs with
    /// bootstrap deadlines and no stored revision. Nothing is created
    /// under the root before construction, so this passes on every
    /// runner.
    #[test]
    fn build_on_an_absent_cache_tree_is_the_first_boot() {
        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-s9-boot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = ConfigPaths::rooted(&dir);

        let services =
            DaemonServices::build_with_trust_root(&SystemConfig::default(), &paths, &dir)
                .expect("first boot constructs the scheduler");
        // The FR-13F bootstrap: never fetched, so everything is due.
        assert_eq!(services.scheduler.next_due_unix(), None);
        assert_eq!(
            services.cached_catalog().expect("absent cache is clean"),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The suppression path, end to end through the REAL bridge: a
    /// rate-limited adapter behind the provider cell drives the
    /// scheduler's manual refresh into `Suppressed` — the path that was
    /// production-dead before obligation (b).
    #[test]
    fn a_rate_limited_adapter_behind_the_bridge_mints_a_suppression() {
        use protonwire_core::scheduler::ManualOutcome;

        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-s9-sup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = ConfigPaths::rooted(&dir);
        let services =
            DaemonServices::build_with_trust_root(&SystemConfig::default(), &paths, &dir)
                .expect("first boot");
        services.catalog.install(Arc::new(FakeCatalog::always(|| {
            Err(ApiError::RateLimited {
                retry_after_seconds: Some(60),
            })
        })));

        // First refresh: the rate limit REPORTS (the report carries the
        // suppression the deadline computation minted)...
        match services.scheduler.refresh_manual(None) {
            ManualOutcome::Refreshed(report) => {
                let wire = refresh_report_to_wire(report);
                assert_eq!(
                    wire.outcome,
                    ServersRefreshOutcome::RateLimited {
                        retry_after_seconds: Some(60),
                    }
                );
                assert!(wire.suppression_until_unix.is_some());
            }
            other => panic!("the first manual refresh must run, got {other:?}"),
        }
        // ...and the minted suppression refuses the NEXT attempt outrank
        // even a confirmed manual refresh (ER-16).
        match services.scheduler.refresh_manual(None) {
            ManualOutcome::Suppressed { .. } => {}
            other => panic!("the suppression must refuse the next manual refresh: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
