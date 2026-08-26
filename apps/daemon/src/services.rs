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
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;

use protonwire_api::{ApiError, AuthenticationApi, CatalogApi, CatalogFetch, LoginStatus};
use protonwire_core::redact::PeerSecret;
use protonwire_core::scheduler::CatalogFetch as SchedulerFetch;
use protonwire_core::scheduler::{
    FetchFailure, FetchOutcome, Scheduler, SchedulerConfig, SchedulerError, SystemClock,
};
use protonwire_frontend_api::CredentialStartupRead;
use protonwire_frontend_api::ServersRefreshOutcome;
use protonwire_frontend_api::ServersRefreshReport;
use protonwire_store::catalog::CatalogCache;
use protonwire_store::catalog::CatalogCacheError;
use protonwire_store::config::SystemConfig;
use protonwire_store::credential_input::CREDENTIALS_DIRECTORY_VAR;
use protonwire_store::credential_input::CredentialInputError;
use protonwire_store::credential_input::CredentialSource;
use protonwire_store::credential_input::InteractiveProvider;
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
    /// The configured credential INPUT source could not be resolved
    /// (FR-7J: a systemd source with no systemd credentials directory
    /// behind it is a misdeployment, refused at startup rather than
    /// silently blank).
    #[error("credential input source resolution failed: {0}")]
    Credentials(#[from] CredentialInputError),
}

/// The interactive credential store: the backer of S5a's
/// [`InteractiveProvider`] (the S9 IPC seam). Values arrive through
/// `SubmitCredential` and cross the daemon boundary straight into
/// `peer_secret` guarded storage — zeroizing, never in the global
/// scrub registry (the M1 finding-10 rule; the S5a module docs record
/// the boundary contract and its landed core impl).
#[derive(Default)]
pub struct CredentialStore {
    values: RwLock<std::collections::HashMap<String, PeerSecret>>,
}

/// The interactive credential vocabulary — the proto's documented short
/// names (frontend-api `SubmitCredential`): the store is bounded to
/// exactly these keys. Unbounded peer-supplied names × frame-sized
/// values × no eviction was a memory-exhaustion lever against the root
/// daemon from any socket-group peer (the S9 sec review's P2 — the
/// M1 finding-10 class); the bound lives at the STORE (the asset), not
/// only the handler.
pub const INTERACTIVE_CREDENTIAL_NAMES: [&str; 3] = ["session", "username", "password"];

impl CredentialStore {
    /// Records one credential value under its short name (replacing any
    /// previous value — the newest submission wins). Refuses names
    /// outside [`INTERACTIVE_CREDENTIAL_NAMES`] with the vocabulary's
    /// message for the wire; the value is the caller's to drop.
    pub fn submit(&self, name: &str, value: PeerSecret) -> Result<(), &'static str> {
        if !INTERACTIVE_CREDENTIAL_NAMES.contains(&name) {
            return Err(
                "unknown credential short name (the vocabulary is: session, username, password)",
            );
        }
        self.values
            .write()
            .expect("credential store lock")
            .insert(name.to_owned(), value);
        Ok(())
    }

    /// True when no credential has landed — the bound's observable:
    /// refused submissions never occupy entries.
    pub fn is_empty(&self) -> bool {
        self.values
            .read()
            .expect("credential store lock")
            .is_empty()
    }

    /// Reads one credential value by short name (the provider half).
    pub fn get(&self, name: &str) -> Option<PeerSecret> {
        self.values
            .read()
            .expect("credential store lock")
            .get(name)
            .cloned()
    }

    /// The S5a [`InteractiveProvider`] closure over a shared store —
    /// the seam `CredentialSource::read` consults.
    pub fn provider(self: &Arc<Self>) -> InteractiveProvider<PeerSecret> {
        let store = Arc::clone(self);
        Arc::new(move |name| store.get(name))
    }
}

/// The resolved credential input (S9 obligation d) plus the facts the
/// `GetAccount` snapshot reports.
pub struct CredentialInput {
    /// The live source (interactive provider or systemd directory).
    pub source: CredentialSource<PeerSecret>,
    /// The systemd arm's recorded startup read of the preferred
    /// `session` credential (facts only, never value bytes; `None` for
    /// the interactive arm, which carries no startup read on the wire).
    pub startup_read: Option<CredentialStartupRead>,
    /// The systemd arm's resolved credentials directory (reporting
    /// only); `None` for the interactive arm.
    pub directory: Option<PathBuf>,
}

/// Resolves the configured credential input source over an injected
/// credentials directory (`None` = the systemd arm's hard FR-7J
/// refusal — the production caller passes the `$CREDENTIALS_DIRECTORY`
/// value it read from the environment; the injection seam exists
/// because edition-2024 `set_var` is `unsafe` and the workspace denies
/// `unsafe_code`).
///
/// The systemd arm's startup read of the preferred `session`
/// credential happens HERE, once: a `Read` fact records the envelope's
/// schema version, a refusal records the typed error's value-free
/// summary (the transactional import is S5b's; this is the input-half
/// fact the wire model carries).
///
/// # Errors
/// [`CredentialInputError`] — see the S5a module docs for the
/// fail-closed matrix (the resolution arms: no/empty credentials
/// directory).
pub fn resolve_credential_input_in(
    config: &SystemConfig,
    directory: Option<&Path>,
    store: Arc<CredentialStore>,
) -> Result<CredentialInput, CredentialInputError> {
    let source = CredentialSource::resolve_in(
        config.account.credential_input_source,
        &config.account,
        directory,
        store.provider(),
    )?;
    // The systemd arm's startup read: recorded ONCE here, never
    // re-read mid-run (the interactive arm carries no startup read).
    let (startup_read, systemd_dir) = match &source {
        CredentialSource::Interactive { .. } => (None, None),
        CredentialSource::Systemd(dir) => (
            Some(match source.read_session_envelope() {
                Ok(envelope) => CredentialStartupRead::Read {
                    schema_version: envelope.schema_version,
                },
                Err(error) => CredentialStartupRead::Refused {
                    reason: error.to_string(),
                },
            }),
            Some(dir.directory().to_path_buf()),
        ),
    };
    Ok(CredentialInput {
        source,
        startup_read,
        directory: systemd_dir,
    })
}

/// The live daemon services the request handler dispatches into.
pub struct DaemonServices {
    /// The single-flight catalog scheduler (FR-13C: one per process).
    pub scheduler: Arc<Scheduler>,
    /// The catalog adapter cell + the scheduler's fetch bridge.
    pub catalog: Arc<CatalogService>,
    /// The authentication adapter cell (the login family's provider).
    pub auth: AuthProvider,
    /// The interactive credential store (`SubmitCredential`'s landing;
    /// the interactive source's provider backer).
    pub credentials: Arc<CredentialStore>,
    /// The resolved credential input source + its startup-read facts.
    pub credential_input: CredentialInput,
    /// The validated system configuration (the `GetAccount`
    /// snapshot's writable-store facts).
    pub config: Arc<SystemConfig>,
    /// The strict-loaded catalog cache document location (the
    /// `ServersList` read side; the scheduler is the only writer).
    pub cache_file: std::path::PathBuf,
    /// The fs_trust root every strict load here walks to — `/` in
    /// production, the hermetic root in tests (the same opt-in the
    /// construction takes).
    trust_root: std::path::PathBuf,
    /// The U6 selection engine (the `Select`/`GroupsList`/`GroupShow`
    /// body): the cached-catalog read, the FR-23Q composition, the S8
    /// entitlement cell, and the bounded on-demand prober.
    pub selection: crate::selection::SelectionEngine,
}

impl DaemonServices {
    /// The production construction: derives the scheduler policy from
    /// the validated system configuration, resolves the credential
    /// input source (`$CREDENTIALS_DIRECTORY` read from the
    /// environment), and constructs the scheduler STRICTLY over the
    /// `ConfigPaths` cache directory with `/` as the fs_trust root.
    ///
    /// # Errors
    /// [`ServiceStartupError`] — see its variants' docs for the
    /// fail-closed contract (abort startup; never default deadlines,
    /// never a silently-blank credential source).
    pub fn build(
        config: Arc<SystemConfig>,
        paths: &ConfigPaths,
    ) -> Result<Self, ServiceStartupError> {
        Self::build_in(
            config,
            paths,
            Path::new("/"),
            std::env::var_os(CREDENTIALS_DIRECTORY_VAR),
        )
    }

    /// The hermetic-test construction over an explicit fs_trust root
    /// (the same opt-in the core-side
    /// `Scheduler::production_with_trust_root` documents): an
    /// unprivileged runner cannot make a tree root-owned, so the
    /// ownership pass would refuse every test-planted document before
    /// the arm under test. The credentials directory stays the
    /// environment's (the interactive default needs none; a systemd
    /// misdeployment test plants its config and relies on the variable
    /// being absent).
    ///
    /// # Errors
    /// As [`Self::build`].
    pub fn build_with_trust_root(
        config: Arc<SystemConfig>,
        paths: &ConfigPaths,
        trust_root: &Path,
    ) -> Result<Self, ServiceStartupError> {
        Self::build_in(
            config,
            paths,
            trust_root,
            std::env::var_os(CREDENTIALS_DIRECTORY_VAR),
        )
    }

    /// The common construction: both seams injectable (trust root,
    /// credentials directory).
    fn build_in(
        config: Arc<SystemConfig>,
        paths: &ConfigPaths,
        trust_root: &Path,
        credentials_directory: Option<std::ffi::OsString>,
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
        let credentials = Arc::new(CredentialStore::default());
        let credential_input = resolve_credential_input_in(
            &config,
            credentials_directory.as_deref().map(Path::new),
            Arc::clone(&credentials),
        )?;
        Ok(Self {
            scheduler,
            catalog,
            auth: AuthProvider::default(),
            credentials,
            credential_input,
            config: Arc::clone(&config),
            cache_file: paths.cache_dir.join("servers.json"),
            trust_root: trust_root.to_path_buf(),
            selection: crate::selection::SelectionEngine::new(config, &paths.cache_dir, trust_root),
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

    /// Assembles the `GetAccount` snapshot (FR-7H): login status through
    /// the auth provider cell (an empty cell is LoggedOut — no session
    /// exists), the resolved credential source with its startup-read
    /// facts, and the configured writable-store declarations. Facts
    /// only, never a fabricated field; `persistence_health` stays
    /// absent until its owner reports it (S5b/S5c).
    ///
    /// # Errors
    /// [`protonwire_frontend_api::RpcError`] when the adapter's login
    /// status cannot be determined (mapped by [`api_error_to_rpc`]).
    pub fn account_status(
        &self,
    ) -> Result<protonwire_frontend_api::AccountStatus, protonwire_frontend_api::RpcError> {
        use protonwire_frontend_api::{AccountStatus, CredentialSourceStatus, SessionStatus};

        let login_status = match self.auth.current() {
            Some(auth) => login_status_to_wire(auth.login_status().map_err(api_error_to_rpc)?),
            // No engine installed: no session exists.
            None => SessionStatus::LoggedOut,
        };
        let credential_source = match &self.credential_input.source {
            CredentialSource::Interactive { .. } => CredentialSourceStatus::Interactive,
            CredentialSource::Systemd(dir) => CredentialSourceStatus::Systemd {
                directory: dir.directory().display().to_string(),
                startup_read: self.credential_input.startup_read.clone().unwrap_or(
                    protonwire_frontend_api::CredentialStartupRead::Refused {
                        reason: "the startup read was not recorded".to_owned(),
                    },
                ),
            },
        };
        Ok(AccountStatus {
            login_status,
            credential_source,
            writable_store: protonwire_frontend_api::WritableStoreStatus {
                declared: self
                    .config
                    .account
                    .writable_session_store
                    .as_str()
                    .to_owned(),
                priority: self
                    .config
                    .account
                    .writable_store_priority
                    .iter()
                    .map(|entry| entry.as_str().to_owned())
                    .collect(),
            },
            // S5b/S5c own the writable-store half; the field stays
            // absent — never fabricated.
            persistence_health: None,
        })
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

    /// A fake catalog adapter scripting one result per call
    /// (`ApiError` is not `Clone` — it owns its detail strings — so the
    /// fake produces a fresh result per call). Shared by the services
    /// suite and the automatic-refresh driver suite (the driver's
    /// fetch-count observable).
    pub(crate) struct FakeCatalog {
        produce: Box<dyn Fn() -> Result<CatalogFetch, ApiError> + Send + Sync>,
    }

    impl FakeCatalog {
        /// A fake whose every fetch produces `produce()`'s result.
        pub(crate) fn always(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::testkit::{FakeAuth, FakeCatalog};

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

        let err =
            DaemonServices::build_with_trust_root(Arc::new(SystemConfig::default()), &paths, &dir)
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
            DaemonServices::build_with_trust_root(Arc::new(SystemConfig::default()), &paths, &dir)
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
            DaemonServices::build_with_trust_root(Arc::new(SystemConfig::default()), &paths, &dir)
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

    // --- S9 (d): the credential input wiring ------------------------------

    use protonwire_core::redact::peer_secret;
    use protonwire_store::config::CredentialInputSource as Vocabulary;
    use std::os::unix::fs::PermissionsExt as _;

    /// (d) The IPC-driven interactive loop: `SubmitCredential`'s landing
    /// (the store) feeds S5a's `InteractiveProvider`, and the source's
    /// own `read` serves the submitted value through the boundary —
    /// the guarded type never renders its value (Debug is `[redacted]`)
    /// and a blank submission is refused by the source's blankness
    /// gate (S5a's fail-closed symmetry, exercised through the real
    /// `CredentialSource::read`).
    #[test]
    fn submit_credential_feeds_the_interactive_provider() {
        let store = Arc::new(CredentialStore::default());
        let source = CredentialSource::resolve_in(
            Vocabulary::Interactive,
            &SystemConfig::default().account,
            None,
            store.provider(),
        )
        .expect("the interactive source needs no directory");

        // Nothing submitted: the typed NotProvided refusal.
        match source.read("session") {
            Err(CredentialInputError::NotProvided { name }) => assert_eq!(name, "session"),
            other => panic!("nothing submitted must refuse NotProvided: {other:?}"),
        }
        // A submitted value serves through the boundary, newest wins.
        store.submit("session", peer_secret("first")).unwrap();
        store.submit("session", peer_secret("second")).unwrap();
        let served = source.read("session").expect("the submitted value serves");
        assert_eq!(served.expose(), "second");
        assert_eq!(format!("{served:?}"), "[redacted]");
        // A blank is never a credential (the source's own gate).
        store.submit("username", peer_secret("")).unwrap();
        match source.read("username") {
            Err(CredentialInputError::ProvidedEmpty { name }) => assert_eq!(name, "username"),
            other => panic!("a blank must refuse ProvidedEmpty: {other:?}"),
        }
    }

    /// (d) The interactive arm records NO startup read (the wire model
    /// carries the fact only for the systemd arm).
    #[test]
    fn interactive_resolution_records_no_startup_read() {
        let input = resolve_credential_input_in(
            &SystemConfig::default(),
            None,
            Arc::new(CredentialStore::default()),
        )
        .expect("the interactive default resolves without a directory");
        assert!(input.startup_read.is_none());
        assert!(input.directory.is_none());
    }

    /// (d) FR-7J, resolution arm: a configured systemd source with NO
    /// credentials directory is a misdeployment — the typed refusal the
    /// daemon's startup aborts on.
    #[test]
    fn systemd_source_without_a_directory_refuses_resolution() {
        let mut config = SystemConfig::default();
        config.account.credential_input_source = Vocabulary::Systemd;
        let err = resolve_credential_input_in(&config, None, Arc::new(CredentialStore::default()))
            .err()
            .expect("the misdeployment must refuse");
        assert!(
            matches!(err, CredentialInputError::NoCredentialsDirectory),
            "the FR-7J refusal: {err}"
        );
    }

    /// (d) The systemd arm's startup read is recorded ONCE at
    /// resolution: a `Refused` fact for a directory missing the
    /// preferred `session` credential (the username/password bootstrap
    /// pair may legitimately be what was provisioned — a refused
    /// startup read is a FACT, not an abort), and a `Read` fact with
    /// the envelope's schema version when a current envelope is
    /// readable. Arm disclosure: the `Read` arm's fs_trust walk needs
    /// a root-owned tree (NOTICE-skip unprivileged — the a368775
    /// idiom); the refusal matrix itself is pinned by the store suite.
    #[test]
    fn systemd_startup_read_records_the_typed_fact() {
        use std::os::unix::fs::MetadataExt;

        let mut config = SystemConfig::default();
        config.account.credential_input_source = Vocabulary::Systemd;
        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-s9-cred-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Missing credential: the Refused fact names the typed error.
        let input =
            resolve_credential_input_in(&config, Some(&dir), Arc::new(CredentialStore::default()))
                .expect("the directory itself resolves");
        assert_eq!(input.directory.as_deref(), Some(dir.as_path()));
        match input.startup_read {
            Some(CredentialStartupRead::Refused { reason }) => assert!(
                reason.contains("missing") || reason.contains("untrusted"),
                "the refusal fact carries the typed reason (missing leaf or the \
                 unprivileged ownership walk): {reason}"
            ),
            other => panic!("a missing credential must record a Refused fact: {other:?}"),
        }

        // A current, integral envelope: the Read fact. Root-gated (the
        // walk's ownership pass); the store suite pins the parse arms.
        let envelope =
            protonwire_store::session::SessionEnvelope::new(serde_json::json!({"k": "v"}))
                .expect("the envelope mints its own digest");
        let leaf = dir.join("protonwire-session");
        std::fs::write(&leaf, serde_json::to_string(&envelope).unwrap()).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o400)).unwrap();
        let root_owned = std::fs::metadata(&leaf)
            .map(|m| m.uid() == 0 && m.gid() == 0)
            .unwrap_or(false);
        let input =
            resolve_credential_input_in(&config, Some(&dir), Arc::new(CredentialStore::default()))
                .expect("the directory itself resolves");
        if root_owned {
            match input.startup_read {
                Some(CredentialStartupRead::Read { schema_version }) => assert_eq!(
                    schema_version,
                    protonwire_store::session::SESSION_SCHEMA_VERSION
                ),
                other => panic!("an integral envelope must record a Read fact: {other:?}"),
            }
        } else {
            eprintln!(
                "NOTICE: the Read arm of systemd_startup_read_records_the_typed_fact needs a \
                 root-owned credentials tree; the unprivileged run pins the Refused arm and the \
                 resolution facts (visible via --nocapture)"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
