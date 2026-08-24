//! Daemon-side plumbing shared by `main` and tests: the event-sink bridge,
//! the request handler that couples core to the admin stop flag, the M2
//! S11 per-UID configuration consult
//! ([`DaemonHandler::effective_config_for`]), and the automatic
//! catalog-refresh driver
//! ([`automatic_refresh_driver`]/[`spawn_automatic_refresh_driver`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use protonwire_core::DaemonCore;
use protonwire_core::scheduler::ManualOutcome;
use protonwire_frontend_api::{Request, RequestResult, RpcError, RpcErrorCode};
use protonwire_ipc::{EventBus, RequestHandler, SessionContext};

use std::path::{Path, PathBuf};

pub mod services;

pub use services::DaemonServices;

/// Resolves where the IPC server binds (Codex PR review finding 4):
/// the `--socket-dir` CLI override wins, then the config document's
/// `daemon.socket_path` (split into directory and name), then the default
/// `ConfigPaths` location. Pure so the precedence is unit-testable —
/// `main` only wires it into
/// [`protonwire_ipc::server::IpcServer::bind_with_group`] (with
/// `daemon.socket_group` alongside, pr-champion WO-7).
pub fn resolve_bind_location(
    cli_socket_dir: Option<&Path>,
    config_socket_path: Option<&str>,
    default_dir: &Path,
    default_name: &str,
) -> (PathBuf, String) {
    if let Some(dir) = cli_socket_dir {
        return (dir.to_path_buf(), default_name.to_owned());
    }
    if let Some(path) = config_socket_path {
        let path = Path::new(path);
        let dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(default_name);
        return (dir.to_path_buf(), name.to_owned());
    }
    (default_dir.to_path_buf(), default_name.to_owned())
}
/// Bridges core events to the IPC event bus.
pub struct BusSink(pub Arc<EventBus>);

impl protonwire_core::EventSink for BusSink {
    fn publish(&self, event: protonwire_frontend_api::EventEnvelope) {
        self.0
            .publish(protonwire_frontend_api::ServerMessage::Event(event));
    }
}

/// Serves core requests plus the admin shutdown path.
pub struct DaemonHandler {
    /// The authoritative state machine.
    pub core: Arc<DaemonCore>,
    /// Set when an administrator requests shutdown; the serve loop exits.
    pub stop: Arc<AtomicBool>,
    /// Event fan-out shared with sessions.
    pub bus: Arc<EventBus>,
    /// The S9 service surface (scheduler, catalog bridge) — constructed
    /// strictly at startup; fail-closed, so every handler can rely on
    /// it existing.
    pub services: Arc<DaemonServices>,
}

impl RequestHandler for DaemonHandler {
    fn daemon_version(&self) -> &str {
        self.core.version()
    }

    fn latest_event_seq(&self) -> u64 {
        self.core.latest_event_seq()
    }

    fn handle(&self, ctx: &SessionContext, request: Request) -> Result<RequestResult, RpcError> {
        match request {
            Request::Shutdown => {
                // authz already restricted this to administrator peers.
                tracing::info!(uid = ctx.peer.uid, "administrator requested shutdown");
                self.stop.store(true, Ordering::SeqCst);
                Ok(RequestResult::Acknowledged)
            }
            // S2's redaction decision (PRD 6.3): the full-state snapshot
            // hides the active owner's UID from every peer that is
            // neither the owner nor root — null active_owner_uid.
            Request::GetState => {
                let mut state = self.core.state();
                redact_state_for_peer(&mut state, ctx.peer.uid);
                Ok(RequestResult::State { state })
            }
            // (d) The interactive credential source's IPC feed: the
            // value crosses the daemon boundary straight into guarded
            // peer-secret storage (zeroizing, never the scrub
            // registry) keyed by its short name — bounded to the
            // documented vocabulary at the store (the S9 sec P2).
            Request::SubmitCredential { name, value } => {
                self.services
                    .credentials
                    .submit(&name, protonwire_core::redact::peer_secret(value.expose()))
                    .map_err(|detail| RpcError::new(RpcErrorCode::InvalidParams, detail))?;
                Ok(RequestResult::Acknowledged)
            }
            // FR-7H's snapshot behind `account --json`: facts only,
            // never a fabricated field.
            Request::GetAccount => {
                let account = self.services.account_status()?;
                Ok(RequestResult::Account { account })
            }
            // FR-10: serve the cached revision verbatim — no upstream
            // request. An absent cache is the legitimate nothing-yet
            // state (all-None fields); a PRESENT cache that fails the
            // strict load fails closed.
            Request::ServersList => match self.services.cached_catalog() {
                Ok(Some(cached)) => Ok(RequestResult::Servers {
                    etag: cached.etag,
                    fetched_unix: Some(cached.fetched_unix),
                    body: Some(cached.body),
                }),
                Ok(None) => Ok(RequestResult::Servers {
                    etag: None,
                    fetched_unix: None,
                    body: None,
                }),
                Err(error) => Err(RpcError::new(
                    RpcErrorCode::ConfigInvalid,
                    format!("cached catalog failed the strict load: {error}"),
                )),
            },
            // FR-11/FR-13I through the single-flight scheduler: eligible
            // refreshes run, early ones demand the warned confirmation,
            // and an active suppression outranks even a confirmed retry
            // (ER-16 — the refusal code carries the pacing facts).
            Request::ServersRefresh { confirmation_token } => {
                match self
                    .services
                    .scheduler
                    .refresh_manual(confirmation_token.as_deref())
                {
                    ManualOutcome::Refreshed(report) => Ok(RequestResult::ServersRefreshed {
                        report: services::refresh_report_to_wire(report),
                    }),
                    ManualOutcome::ConfirmationRequired(requirement) => {
                        Err(RpcError::confirmation_required(
                            "the server list is still fresh; confirm to refresh now anyway",
                            requirement,
                        ))
                    }
                    ManualOutcome::Suppressed { until_unix } => Err(RpcError::new(
                        RpcErrorCode::RateLimited,
                        format!(
                            "a rate-limit suppression is active until Unix time {until_unix}; \
                             no path may bypass it (ER-16)"
                        ),
                    )),
                    ManualOutcome::Unavailable => Err(RpcError::new(
                        RpcErrorCode::Internal,
                        "the confirmation ceremony is unavailable (CSPRNG failure); \
                         no early manual refresh is possible",
                    )),
                }
            }
            // The login family: through the auth provider cell. An
            // empty cell (the engine wiring is the session lane's) is
            // a typed NotImplemented — never a fabricated login state.
            // The five arms share the guard via `with_auth`.
            Request::BeginLogin { username, password } => self.with_auth(|auth| {
                let step =
                    services::begin_login_guarded(auth, username.expose(), password.expose())
                        .map_err(services::api_error_to_rpc)?;
                Ok(RequestResult::LoginStep {
                    step: services::login_step_to_wire(step),
                })
            }),
            Request::SubmitTwoFactor { code } => self.with_auth(|auth| {
                let step = auth
                    .submit_two_factor(code.expose())
                    .map_err(services::api_error_to_rpc)?;
                Ok(RequestResult::LoginStep {
                    step: services::login_step_to_wire(step),
                })
            }),
            Request::SubmitFidoPayload {
                client_data,
                authenticator_data,
                signature,
                credential_id,
            } => self.with_auth(|auth| {
                let payload = protonwire_api::Fido2Payload {
                    client_data: client_data.expose().to_owned(),
                    authenticator_data: authenticator_data.expose().to_owned(),
                    signature: signature.expose().to_owned(),
                    credential_id,
                };
                let step = auth
                    .submit_fido_payload(&payload)
                    .map_err(services::api_error_to_rpc)?;
                Ok(RequestResult::LoginStep {
                    step: services::login_step_to_wire(step),
                })
            }),
            Request::RefreshSession => self.with_auth(|auth| {
                let status = auth.refresh().map_err(services::api_error_to_rpc)?;
                Ok(RequestResult::LoginStatus {
                    status: services::login_status_to_wire(status),
                })
            }),
            Request::Logout => self.with_auth(|auth| {
                // FR-4: best-effort remote teardown, guaranteed
                // local credential removal (Muon's logout is
                // infallible by design; a transport failure is
                // reported but the local state is the adapter's).
                auth.logout().map_err(services::api_error_to_rpc)?;
                Ok(RequestResult::Acknowledged)
            }),
            other => self.core.handle_request(ctx.peer.uid, other),
        }
    }

    fn event_bus(&self) -> &EventBus {
        &self.bus
    }
}

impl DaemonHandler {
    /// Runs `call` against the installed auth adapter — the login
    /// family's shared empty-cell guard: no adapter installed (the
    /// engine wiring is the session lane's) is the typed
    /// [`no_engine_installed`] refusal, never a fabricated login state.
    fn with_auth<T>(
        &self,
        call: impl FnOnce(&dyn protonwire_api::AuthenticationApi) -> Result<T, RpcError>,
    ) -> Result<T, RpcError> {
        match self.services.auth.current() {
            Some(auth) => call(auth.as_ref()),
            None => Err(no_engine_installed()),
        }
    }
}

/// The login family's empty-cell refusal: the session engine (the
/// MuonAuth construction and runtime wiring) is the api lane's
/// deliverable; until it installs its adapter, the family answers with
/// a typed refusal instead of a fabricated state.
fn no_engine_installed() -> RpcError {
    RpcError::new(
        RpcErrorCode::NotImplemented,
        "the account session engine is not wired yet (the session lane \
         installs it into the daemon's auth provider)",
    )
}

/// S2's GetState redaction decision (PRD 6.3, the round-1 finding-9
/// close-out): a peer that is neither the active connection owner nor
/// root sees `active_owner_uid: null` — the owner's identity is not
/// cross-user observable. Pure so the decision matrix is unit-testable;
/// the handler wiring is type-checked (no daemon-side test can record
/// an owner yet — the M4 engine owns that transition — so the pure
/// matrix is the enforceable pin, the `config_socket_group`
/// pass-through precedent).
pub fn redact_state_for_peer(state: &mut protonwire_frontend_api::DaemonState, peer_uid: u32) {
    if let Some(owner) = state.active_owner_uid
        && peer_uid != owner
        && peer_uid != 0
    {
        state.active_owner_uid = None;
    }
}

/// The M2 S11 / T-37 consult surface, implemented on the handler so
/// every config-derived answer for a peer goes through one door. The
/// plan's granularity: S11 lands the loader and this daemon-side seam;
/// the request-handler integration rides with the overlay IPC wire
/// surface (the S2 lane's `Request` family — the client's typed-overlay
/// submission per PRD section 10), whose handlers call this method.
impl DaemonHandler {
    /// The effective configuration for the REQUESTING peer: the system
    /// document with the peer's per-UID overlay merged over it per the
    /// authority classes (system fields untouched by construction;
    /// present per-user fields applied; the permanent kill-switch floor
    /// enforced; cross-field rules re-validated on the merged document).
    ///
    /// UID provenance (SEC-27): the overlay is keyed by
    /// `ctx.peer.uid` — the kernel-provided Unix peer credential read at
    /// connection time. There is NO client-supplied uid in the consult
    /// (none exists on this wire), and the store derives the document
    /// path from the raw integer
    /// (`protonwire_store::config::overlay_path`), so a peer cannot name
    /// another UID's document — it can only be answered by its own.
    ///
    /// `overlay_base` is the daemon-owned overlay tree (production:
    /// `protonwire_store::config::PRODUCTION_OVERLAY_BASE`); a missing
    /// document for the peer is the no-overlay state and yields the
    /// system document unchanged. A PRESENT document that fails any
    /// check — a system-authority key, the anchor policy, schema drift,
    /// or a cross-field violation against the system values — is the
    /// typed [`RpcErrorCode::ConfigInvalid`] refusal: the caller answers
    /// fail-closed, never from a silently half-applied policy and never
    /// from an unnotified system-only fallback.
    pub fn effective_config_for(
        &self,
        ctx: &SessionContext,
        overlay_base: &Path,
    ) -> Result<protonwire_store::config::SystemConfig, RpcError> {
        protonwire_store::config::effective_config(
            self.services.config.as_ref(),
            overlay_base,
            ctx.peer.uid,
        )
        .map_err(|error| RpcError::new(RpcErrorCode::ConfigInvalid, error.to_string()))
    }
}

/// The longest the automatic-refresh driver ever sleeps without
/// re-checking the stop flag: stop latency stays sub-second no matter
/// how far out the next window is.
pub const DRIVER_STOP_POLL_SLICE: std::time::Duration = std::time::Duration::from_millis(500);

/// Drives the scheduler's AUTOMATIC refresh door (FR-12/FR-13C): a
/// stop-aware loop that sleeps to the next eligibility
/// (`Scheduler::next_due_unix`; `None`
/// is the FR-13F bootstrap — never fetched, due immediately) and calls
/// `Scheduler::refresh_automatic` when
/// the window opens. Constructing the scheduler services no window by
/// itself: without this loop the first-boot due window is never
/// fetched and persisted deadlines are never honored when they become
/// due — catalog freshness would depend entirely on a user issuing
/// `ServersRefresh` (the Codex PR#4 P1).
///
/// Determinism seams: `now_unix` and `sleep_for` are injected — the
/// scheduler's own policy decisions stay on ITS clock; the driver only
/// decides how long to wait. Waits are sliced at
/// [`DRIVER_STOP_POLL_SLICE`] so a stop request is honored promptly
/// mid-wait. Every refresh outcome is logged (a rate-limited or failed
/// window names its reason; the suppression the scheduler minted is
/// honored by `Scheduler::refresh_automatic` itself).
pub fn automatic_refresh_driver(
    scheduler: &protonwire_core::scheduler::Scheduler,
    stop: &AtomicBool,
    mut now_unix: impl FnMut() -> u64,
    mut sleep_for: impl FnMut(std::time::Duration),
) {
    use protonwire_core::scheduler::AutomaticOutcome;
    use protonwire_core::scheduler::RefreshOutcome;

    while !stop.load(Ordering::SeqCst) {
        // None = the FR-13F bootstrap: due immediately.
        let wait_secs = scheduler
            .next_due_unix()
            .map_or(0, |due| due.saturating_sub(now_unix()));
        if wait_secs > 0 {
            // Sleep to the deadline in stop-responsive slices.
            let mut remaining = std::time::Duration::from_secs(wait_secs);
            while !stop.load(Ordering::SeqCst) && !remaining.is_zero() {
                let slice = remaining.min(DRIVER_STOP_POLL_SLICE);
                sleep_for(slice);
                remaining = remaining.saturating_sub(slice);
            }
            continue;
        }
        match scheduler.refresh_automatic() {
            AutomaticOutcome::Due(report) => match report.outcome {
                RefreshOutcome::Changed { etag, .. } => tracing::info!(
                    etag = ?etag,
                    next_eligible_unix = report.next_eligible_unix,
                    "automatic catalog refresh: new revision"
                ),
                RefreshOutcome::NotModified => tracing::info!(
                    next_eligible_unix = report.next_eligible_unix,
                    "automatic catalog refresh: revision unchanged"
                ),
                RefreshOutcome::RateLimited {
                    retry_after_seconds,
                } => tracing::warn!(
                    ?retry_after_seconds,
                    suppression_until_unix = ?report.suppression_until_unix,
                    "automatic catalog refresh rate-limited (the scheduler's suppression is honored)"
                ),
                RefreshOutcome::Failed { reason } => tracing::warn!(
                    reason,
                    next_eligible_unix = report.next_eligible_unix,
                    "automatic catalog refresh failed"
                ),
            },
            // Raced a lead from the manual door; the window re-armed —
            // the next iteration recomputes from next_due_unix.
            AutomaticOutcome::NotDue { next_eligible_unix } => tracing::trace!(
                next_eligible_unix,
                "automatic refresh arrived before its window; re-armed"
            ),
        }
    }
}

/// Spawns the production automatic-refresh driver: the real wall clock,
/// real sleeps, stop-flag responsive. `main` joins the handle after
/// `serve` returns, so the daemon never exits with a live refresh in
/// flight.
///
/// # Panics
/// Only if the OS refuses the thread spawn (resource exhaustion at
/// startup — the same fail-loud posture as the bind).
pub fn spawn_automatic_refresh_driver(
    scheduler: Arc<protonwire_core::scheduler::Scheduler>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    use protonwire_core::scheduler::Clock as _;
    use protonwire_core::scheduler::SystemClock;

    std::thread::Builder::new()
        .name("catalog-auto-refresh".to_owned())
        .spawn(move || {
            let clock = SystemClock;
            automatic_refresh_driver(
                scheduler.as_ref(),
                stop.as_ref(),
                || clock.now_unix(),
                std::thread::sleep,
            )
        })
        .expect("spawn the automatic catalog-refresh driver")
}

#[cfg(test)]
mod tests {
    use super::*;
    use protonwire_frontend_api::RpcErrorCode;
    use protonwire_frontend_api::ServersRefreshOutcome;
    use protonwire_store::config::SystemConfig;
    use protonwire_store::paths::ConfigPaths;

    /// A handler over a first-boot services instance: an all-absent
    /// temp cache tree (the FR-13F bootstrap scheduler, no cached
    /// catalog) over the hermetic trust root — passes on every runner.
    /// The directory is unique PER CALL: a test that triggers a refresh
    /// makes the scheduler save (creating the tree), and a later call
    /// re-constructing over an existing non-root-owned tree would fail
    /// the walk's ownership pass by design.
    fn handler_with_config(config: SystemConfig) -> (DaemonHandler, Arc<AtomicBool>) {
        static CALL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "protonwire-daemon-handler-{}-{}",
            std::process::id(),
            CALL.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = ConfigPaths::rooted(&dir);
        let services = Arc::new(
            DaemonServices::build_with_trust_root(Arc::new(config), &paths, &dir)
                .expect("first-boot services construct"),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let core = Arc::new(DaemonCore::new(
            "0.1.0-test",
            Arc::new(SystemConfig::default()),
            Arc::new(BusSink(Arc::new(EventBus::new()))),
        ));
        let handler = DaemonHandler {
            core,
            stop: Arc::clone(&stop),
            bus: Arc::new(EventBus::new()),
            services,
        };
        (handler, stop)
    }

    /// The default handler: default system configuration.
    fn handler() -> (DaemonHandler, Arc<AtomicBool>) {
        handler_with_config(SystemConfig::default())
    }

    fn admin_ctx() -> SessionContext {
        SessionContext {
            peer: protonwire_ipc::PeerCredentials {
                uid: 0,
                gid: 0,
                pid: None,
            },
            client: protonwire_frontend_api::ClientInfo {
                name: "test".into(),
                version: "0".into(),
                surface: protonwire_frontend_api::ClientSurface::Other,
            },
        }
    }

    #[test]
    fn admin_shutdown_sets_stop_flag_and_acknowledges() {
        let (handler, stop) = handler();
        assert!(!stop.load(Ordering::SeqCst));
        match handler.handle(&admin_ctx(), Request::Shutdown).unwrap() {
            RequestResult::Acknowledged => {}
            other => panic!("unexpected result: {other:?}"),
        }
        assert!(stop.load(Ordering::SeqCst));
    }

    #[test]
    fn other_requests_delegate_to_core() {
        let (handler, _) = handler();
        // Ping succeeds through the core delegation.
        match handler
            .handle(&admin_ctx(), Request::Ping { nonce: "n".into() })
            .unwrap()
        {
            RequestResult::Pong { nonce } => assert_eq!(nonce, "n"),
            other => panic!("unexpected result: {other:?}"),
        }
        // Disconnect is refused by core until Milestone 4.
        let err = handler
            .handle(&admin_ctx(), Request::Disconnect)
            .unwrap_err();
        assert_eq!(err.code, RpcErrorCode::NotImplemented);
    }

    /// FR-10: `ServersList` on the first boot is the all-None reply — no
    /// upstream request, no fabricated facts.
    #[test]
    fn servers_list_with_no_cache_answers_all_none() {
        let (handler, _) = handler();
        match handler.handle(&admin_ctx(), Request::ServersList).unwrap() {
            RequestResult::Servers {
                etag,
                fetched_unix,
                body,
            } => {
                assert_eq!(etag, None);
                assert_eq!(fetched_unix, None);
                assert_eq!(body, None);
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    /// The manual refresh door through the handler: the bootstrap window
    /// is due, so the refresh runs; with an empty provider cell the
    /// bridge reports the typed no-adapter transport failure (never a
    /// fabricated success), and the refusal-shaped outcome rides the
    /// wire report.
    #[test]
    fn servers_refresh_runs_the_bootstrap_window_and_reports_the_bridge_failure() {
        let (handler, _) = handler();
        match handler
            .handle(
                &admin_ctx(),
                Request::ServersRefresh {
                    confirmation_token: None,
                },
            )
            .unwrap()
        {
            RequestResult::ServersRefreshed { report } => {
                assert!(!report.coalesced);
                match &report.outcome {
                    ServersRefreshOutcome::Failed { reason } => assert!(
                        reason.contains("no catalog adapter installed"),
                        "the empty-cell refusal must be reported verbatim: {reason}"
                    ),
                    other => panic!("the empty cell must fail the refresh: {other:?}"),
                }
                // The failed attempt still paces: eligibility moved out
                // by at least the three-hour floor.
                assert!(report.suppression_until_unix.is_none());
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    /// S9 (c) at the handler: BeginLogin runs the daemon-side
    /// precondition sequence against the installed adapter — a
    /// logged-in session refuses with the invalid-state semantics
    /// (wire: InvalidParams) and the credentials never reach the
    /// adapter; the empty cell is the typed NotImplemented.
    #[test]
    fn begin_login_refuses_an_occupied_flow_through_the_handler() {
        use crate::services::testkit::FakeAuth;
        use protonwire_api::LoginStatus;
        use protonwire_frontend_api::{RpcErrorCode, SecretParam};

        let (handler, _) = handler();
        // Empty cell: typed refusal, never a fabricated state.
        let err = handler
            .handle(
                &admin_ctx(),
                Request::BeginLogin {
                    username: SecretParam::new("u"),
                    password: SecretParam::new("p"),
                },
            )
            .unwrap_err();
        assert_eq!(err.code, RpcErrorCode::NotImplemented);

        // Installed adapter with a live session: the guard refuses
        // before the adapter's begin_login.
        handler
            .services
            .auth
            .install(std::sync::Arc::new(FakeAuth::new(LoginStatus::LoggedIn)));
        let err = handler
            .handle(
                &admin_ctx(),
                Request::BeginLogin {
                    username: SecretParam::new("u"),
                    password: SecretParam::new("p"),
                },
            )
            .unwrap_err();
        assert_eq!(
            err.code,
            RpcErrorCode::InvalidParams,
            "the invalid-state refusal maps onto the wire code the \
             BeginLogin doc records: {err}"
        );
    }

    /// S9 (e), the redaction decision matrix (the pure pin — the
    /// handler wiring is type-checked; no daemon test can record an
    /// owner before the M4 engine transition): the owner and root see
    /// the owner's UID, every other peer sees null, and a null owner
    /// (no connection) stays null for everyone.
    #[test]
    fn get_state_redacts_the_owner_uid_for_non_owner_non_root_peers() {
        use protonwire_frontend_api::{DaemonState, NetworkIntegration, VpnState};

        fn state_with_owner(owner: Option<u32>) -> DaemonState {
            DaemonState {
                protocol_version: 1,
                daemon_version: "t".into(),
                vpn_state: VpnState::Disconnected,
                network_integration: NetworkIntegration::Auto,
                active_owner_uid: owner,
                latest_event_seq: Some(0),
            }
        }

        // The owner sees its own UID.
        let mut state = state_with_owner(Some(1000));
        redact_state_for_peer(&mut state, 1000);
        assert_eq!(state.active_owner_uid, Some(1000));
        // Root sees it too (PRD 6.3: the administrator is not redacted).
        let mut state = state_with_owner(Some(1000));
        redact_state_for_peer(&mut state, 0);
        assert_eq!(state.active_owner_uid, Some(1000));
        // Any other peer sees null.
        let mut state = state_with_owner(Some(1000));
        redact_state_for_peer(&mut state, 1001);
        assert_eq!(
            state.active_owner_uid, None,
            "the owner's UID is cross-user invisible"
        );
        // No owner recorded: null for everyone (nothing to leak, and
        // the redaction must not fabricate one).
        let mut state = state_with_owner(None);
        redact_state_for_peer(&mut state, 4242);
        assert_eq!(state.active_owner_uid, None);
    }

    /// (d)+(e) through the handler: SubmitCredential lands the guarded
    /// value in the interactive store (served back through the real
    /// source's read), and GetAccount reports the interactive source
    /// with the config's writable-store facts — persistence_health
    /// absent (never fabricated before S5b/S5c). GetState answers with
    /// the redaction applied (a null owner is a no-op here; the
    /// decision matrix is pinned above).
    #[test]
    fn submit_credential_and_get_account_round_trip_the_facts() {
        use protonwire_frontend_api::{CredentialSourceStatus, RequestResult, SecretParam};

        let (handler, _) = handler();
        match handler
            .handle(
                &admin_ctx(),
                Request::SubmitCredential {
                    name: "session".into(),
                    value: SecretParam::new("the-value"),
                },
            )
            .unwrap()
        {
            RequestResult::Acknowledged => {}
            other => panic!("unexpected result: {other:?}"),
        }
        // The submitted value serves through the real source's read
        // path (the interactive provider the source was resolved over).
        let served = handler
            .services
            .credential_input
            .source
            .read("session")
            .expect("the submitted value serves");
        assert_eq!(served.expose(), "the-value");

        match handler.handle(&admin_ctx(), Request::GetAccount).unwrap() {
            RequestResult::Account { account } => {
                assert_eq!(
                    account.login_status,
                    protonwire_frontend_api::SessionStatus::LoggedOut,
                    "no engine installed: no session exists (never fabricated)"
                );
                assert_eq!(
                    account.credential_source,
                    CredentialSourceStatus::Interactive,
                    "the default config source is interactive"
                );
                assert_eq!(account.writable_store.declared, "auto");
                assert!(!account.writable_store.priority.is_empty());
                assert_eq!(
                    account.persistence_health, None,
                    "the writable-store half is S5b/S5c's; never fabricated"
                );
            }
            other => panic!("unexpected result: {other:?}"),
        }
        assert!(matches!(
            handler.handle(&admin_ctx(), Request::GetState).unwrap(),
            RequestResult::State { .. }
        ));
    }

    /// S9 sec P2: the credential store is BOUNDED to the proto's
    /// documented short-name vocabulary — unbounded names × frame-sized
    /// values × no eviction was a memory-exhaustion lever against the
    /// root daemon from any socket-group peer (the M1 finding-10
    /// class). An out-of-vocabulary name is a typed InvalidParams, the
    /// store never sees it.
    #[test]
    fn submit_credential_rejects_names_outside_the_vocabulary() {
        use protonwire_frontend_api::{RequestResult, SecretParam};

        let (handler, _) = handler();
        for junk in ["arbitrary-junk", "session ", "", "x".repeat(512).as_str()] {
            let err = handler
                .handle(
                    &admin_ctx(),
                    Request::SubmitCredential {
                        name: junk.into(),
                        value: SecretParam::new("v"),
                    },
                )
                .expect_err("an out-of-vocabulary name must be refused");
            assert_eq!(
                err.code,
                protonwire_frontend_api::RpcErrorCode::InvalidParams,
                "name {junk:?}"
            );
        }
        // The store itself stayed empty — the bound holds at the
        // asset, not just the handler.
        assert!(
            handler.services.credentials.is_empty(),
            "refused submissions must not occupy store entries"
        );
        // The three documented names still land.
        for good in ["session", "username", "password"] {
            match handler
                .handle(
                    &admin_ctx(),
                    Request::SubmitCredential {
                        name: good.into(),
                        value: SecretParam::new("v"),
                    },
                )
                .unwrap()
            {
                RequestResult::Acknowledged => {}
                other => panic!("unexpected result for {good:?}: {other:?}"),
            }
        }
    }

    // ------------------------------------------------------------------
    // M2 S11 / T-37: the daemon-side consult seam. Red-evidence class:
    // COMPILE-RED (disclosed) — `DaemonHandler::effective_config_for`
    // did not exist on this commit's parent. The store-side behaviors
    // (authority refusal, anchors, merge semantics, the permanent
    // kill-switch floor) carry the behavioral reds in the store suite;
    // these tests pin the DAEMON's half: the consult is keyed by the
    // requesting peer's credential, per-UID isolation at the handler,
    // the typed ConfigInvalid mapping, and the floor through the seam.
    // ------------------------------------------------------------------

    /// A session context for an arbitrary peer uid (the admin fixture
    /// above is just uid 0).
    fn peer_ctx(uid: u32) -> SessionContext {
        SessionContext {
            peer: protonwire_ipc::PeerCredentials {
                uid,
                gid: 1000,
                pid: None,
            },
            client: protonwire_frontend_api::ClientInfo {
                name: "test".into(),
                version: "0".into(),
                surface: protonwire_frontend_api::ClientSurface::Other,
            },
        }
    }

    /// A unique scratch directory for one test's overlay base (the
    /// crate's `main.rs` test idiom — the daemon keeps `tempfile` out of
    /// its dev-dependencies).
    fn temp_base(tag: &str) -> std::path::PathBuf {
        static CALL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "protonwire-daemon-s11-{tag}-{}-{}",
            std::process::id(),
            CALL.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Plants one overlay document for `uid` under `base`.
    fn plant_overlay(base: &Path, uid: u32, document: &str) {
        let dir = base.join(uid.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.yaml"), document).unwrap();
    }

    /// The no-overlay default at the seam: with no document for the
    /// requesting peer, the effective config IS the system document the
    /// services were built over — nothing fabricated, nothing dropped.
    #[test]
    fn effective_config_without_an_overlay_is_the_system_document() {
        let (handler, _) = handler();
        let base = temp_base("none");
        let effective = handler
            .effective_config_for(&peer_ctx(4242), &base.join("absent"))
            .expect("no overlay must consult cleanly");
        assert_eq!(
            serde_json::to_value(&effective).unwrap(),
            serde_json::to_value(SystemConfig::default()).unwrap(),
            "the effective config must be the system document, value for value"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// UID provenance + isolation at the consult point: the same handler
    /// and overlay base answer DIFFERENT effective documents for
    /// different peer credentials — each peer's overlay is keyed by the
    /// kernel-provided `ctx.peer.uid` (the consult signature carries no
    /// client-supplied uid; none exists on this wire). One peer's
    /// overlay is invisible to the other.
    #[test]
    fn effective_config_applies_the_requesting_peers_overlay_and_isolates_uids() {
        let (handler, _) = handler();
        let base = temp_base("iso");
        // uid 1000 lowers the kill switch; uid 1001 raises netshield's
        // level. Each document is only visible to its own credential.
        plant_overlay(
            &base,
            1000,
            "schema_version: 2\nfeatures:\n  kill_switch: off\n",
        );
        plant_overlay(
            &base,
            1001,
            "schema_version: 2\nfeatures:\n  netshield: malware\n",
        );

        let for_1000 = handler
            .effective_config_for(&peer_ctx(1000), &base)
            .unwrap();
        assert_eq!(
            for_1000.features.kill_switch,
            protonwire_store::config::KillSwitchMode::Off,
            "uid 1000's overlay must apply"
        );
        assert_eq!(
            for_1000.features.netshield,
            protonwire_store::config::NetShieldLevel::AdsTrackersMalware,
            "uid 1001's overlay must NOT leak into uid 1000's answer"
        );

        let for_1001 = handler
            .effective_config_for(&peer_ctx(1001), &base)
            .unwrap();
        assert_eq!(
            for_1001.features.netshield,
            protonwire_store::config::NetShieldLevel::Malware,
            "uid 1001's overlay must apply"
        );
        assert_eq!(
            for_1001.features.kill_switch,
            protonwire_store::config::KillSwitchMode::On,
            "uid 1000's overlay must NOT leak into uid 1001's answer"
        );

        // A peer with no document gets the system defaults.
        let for_4242 = handler
            .effective_config_for(&peer_ctx(4242), &base)
            .unwrap();
        assert_eq!(
            for_4242.features.kill_switch,
            protonwire_store::config::KillSwitchMode::On
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The daemon-side revalidation surface (T-37): a hostile overlay —
    /// one attempting a system-authority key — is answered with the
    /// typed ConfigInvalid refusal naming the key, never a silent
    /// system-only fallback the requesting user did not author.
    #[test]
    fn effective_config_refuses_a_system_authority_overlay_with_config_invalid() {
        let (handler, _) = handler();
        let base = temp_base("refuse");
        plant_overlay(
            &base,
            1000,
            "schema_version: 2\ndaemon:\n  log_level: debug\n",
        );
        let err = handler
            .effective_config_for(&peer_ctx(1000), &base)
            .expect_err("a system-authority key must be refused at the consult");
        assert_eq!(err.code, RpcErrorCode::ConfigInvalid);
        assert!(
            err.message.contains("daemon"),
            "the refusal must name the refused key: {}",
            err.message
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The administrator floor through the seam: a daemon whose system
    /// document pins `kill_switch: permanent` hands EVERY peer a
    /// permanent kill switch, whatever the peer's overlay requests.
    #[test]
    fn effective_config_enforces_the_permanent_kill_switch_floor() {
        let mut config = SystemConfig::default();
        config.features.kill_switch = protonwire_store::config::KillSwitchMode::Permanent;
        let (handler, _) = handler_with_config(config);
        let base = temp_base("floor");
        plant_overlay(
            &base,
            1000,
            "schema_version: 2\nfeatures:\n  kill_switch: off\n",
        );
        let effective = handler
            .effective_config_for(&peer_ctx(1000), &base)
            .unwrap();
        assert_eq!(
            effective.features.kill_switch,
            protonwire_store::config::KillSwitchMode::Permanent,
            "the admin's permanent floor must outrank the peer's request"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}

#[cfg(test)]
mod bind_location_tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Codex PR review finding 4 (P2): the documented `daemon.socket_path`
    /// config value was accepted and validated but never applied — binding
    /// always used ConfigPaths/--socket-dir. Precedence under test:
    /// CLI --socket-dir > config daemon.socket_path > default location.
    #[test]
    fn socket_bind_location_precedence() {
        let default_dir = Path::new("/run/protonwire");
        let default_name = "protonwire.sock";

        // CLI flag wins over everything, including the config value.
        assert_eq!(
            resolve_bind_location(
                Some(Path::new("/run/test-cli")),
                Some("/custom/daemon.sock"),
                default_dir,
                default_name,
            ),
            (PathBuf::from("/run/test-cli"), "protonwire.sock".to_owned())
        );

        // Config value wins over the default when no CLI flag is given.
        assert_eq!(
            resolve_bind_location(None, Some("/var/run/alt.sock"), default_dir, default_name),
            (PathBuf::from("/var/run"), "alt.sock".to_owned())
        );

        // Bare name: relative to the working directory, not the default dir.
        assert_eq!(
            resolve_bind_location(None, Some("relative.sock"), default_dir, default_name),
            (PathBuf::from("."), "relative.sock".to_owned())
        );

        // Nothing configured: the documented default.
        assert_eq!(
            resolve_bind_location(None, None, default_dir, default_name),
            (
                PathBuf::from("/run/protonwire"),
                "protonwire.sock".to_owned()
            )
        );
    }
}

/// The automatic-refresh driver suite (the Codex PR#4 P1): the loop
/// that services the scheduler's AUTOMATIC door — construction alone
/// never fetched a window.
#[cfg(test)]
mod driver_tests {
    use super::*;
    use crate::services::testkit::FakeCatalog;
    use protonwire_api::CatalogFetch;
    use protonwire_store::config::SystemConfig;
    use protonwire_store::paths::ConfigPaths;

    /// A first-boot scheduler over the hermetic root with a counting,
    /// always-`NotModified` adapter installed. Returns the services
    /// and a shared event log the adapter and the sleep seam both
    /// append to — the driver's ordering observable (`fetch` entries
    /// vs `sleep` entries, in arrival order).
    fn driven_first_boot() -> (Arc<DaemonServices>, Arc<std::sync::Mutex<Vec<String>>>) {
        static DRIVER_CALL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "protonwire-daemon-driver-{}-{}",
            std::process::id(),
            DRIVER_CALL.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = ConfigPaths::rooted(&dir);
        let services = Arc::new(
            DaemonServices::build_with_trust_root(Arc::new(SystemConfig::default()), &paths, &dir)
                .expect("first-boot services construct"),
        );
        let events: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let sink = Arc::clone(&events);
        services
            .catalog
            .install(Arc::new(FakeCatalog::always(move || {
                sink.lock()
                    .expect("driver event log")
                    .push("fetch".to_owned());
                Ok(CatalogFetch::NotModified)
            })));
        (services, events)
    }

    /// The bootstrap window is serviced AUTOMATICALLY: a first-boot
    /// scheduler (next_due `None` — never fetched, FR-13F) must be
    /// fetched by the driver without any manual `ServersRefresh`, and
    /// the driver must then WAIT for the next window (a capped slice)
    /// rather than spin — the stop flag ends it mid-wait.
    #[test]
    fn the_driver_services_the_bootstrap_window_then_waits_for_the_next_one() {
        let (services, events) = driven_first_boot();
        let stop = Arc::new(AtomicBool::new(false));

        // The sleep seam: record every requested slice; the FIRST one
        // (the wait for the next window) also raises the stop flag —
        // the driver must exit from inside a wait.
        let stop_flag = Arc::clone(&stop);
        let log_sink = Arc::clone(&events);
        let mut first_wait = true;
        let sleep_for = move |slice: std::time::Duration| {
            assert!(
                slice <= DRIVER_STOP_POLL_SLICE,
                "every requested slice is stop-poll capped: {slice:?}"
            );
            log_sink
                .lock()
                .expect("driver event log")
                .push(format!("sleep:{}ms", slice.as_millis()));
            if std::mem::take(&mut first_wait) {
                stop_flag.store(true, Ordering::SeqCst);
            }
        };

        automatic_refresh_driver(&services.scheduler, &stop, || 1_771_000_000, sleep_for);

        let log = events.lock().expect("driver event log").clone();
        assert!(
            log.first().is_some_and(|entry| entry == "fetch"),
            "the bootstrap window must be fetched BEFORE any waiting (the \
             finding's core: construction alone services nothing): {log:?}"
        );
        assert!(
            log.iter().any(|entry| entry.starts_with("sleep:")),
            "after the bootstrap fetch the driver must WAIT for the next \
             window (no hot loop around the refresh door): {log:?}"
        );
        // And the scheduler's window advanced: the next due is the
        // three-hour floor out (or further), never still-open.
        let due = services
            .scheduler
            .next_due_unix()
            .expect("a completed refresh arms the next window");
        assert!(due > 1_771_000_000, "the next window must be in the future");
    }

    /// The ordering pin: when the window is NOT due, the driver waits
    /// first and fetches nothing — the automatic door can never jump
    /// its own deadline (FR-12's floor is the scheduler's to enforce;
    /// the driver must not route around it).
    #[test]
    fn the_driver_never_fetches_before_its_window_opens() {
        let (services, events) = driven_first_boot();
        // A manual bootstrap refresh makes the next window ~3 h out on
        // the REAL clock the scheduler used.
        use protonwire_core::scheduler::ManualOutcome;
        assert!(matches!(
            services.scheduler.refresh_manual(None),
            ManualOutcome::Refreshed(_)
        ));
        let fetched_before = events
            .lock()
            .expect("driver event log")
            .iter()
            .filter(|entry| *entry == "fetch")
            .count();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let mut first_wait = true;
        let sleep_for = move |_slice: std::time::Duration| {
            if std::mem::take(&mut first_wait) {
                stop_flag.store(true, Ordering::SeqCst);
            }
        };
        // The scheduler's deadlines ride the real clock; now must read
        // the same one or every window looks due. A snapshot reading
        // stays before the armed window — the not-due arm under test.
        let base = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the wall clock is past the epoch")
            .as_secs();
        automatic_refresh_driver(&services.scheduler, &stop, || base, sleep_for);

        let fetched_after = events
            .lock()
            .expect("driver event log")
            .iter()
            .filter(|entry| *entry == "fetch")
            .count();
        assert_eq!(
            fetched_before, fetched_after,
            "a not-yet-due window must not be fetched — the driver waits"
        );
    }
}
