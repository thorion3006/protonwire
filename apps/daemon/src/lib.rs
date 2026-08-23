//! Daemon-side plumbing shared by `main` and tests: the event-sink bridge
//! and the request handler that couples core to the admin stop flag.

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
            Request::BeginLogin { username, password } => match self.services.auth.current() {
                Some(auth) => {
                    let step = services::begin_login_guarded(
                        auth.as_ref(),
                        username.expose(),
                        password.expose(),
                    )
                    .map_err(services::api_error_to_rpc)?;
                    Ok(RequestResult::LoginStep {
                        step: services::login_step_to_wire(step),
                    })
                }
                None => Err(no_engine_installed()),
            },
            Request::SubmitTwoFactor { code } => match self.services.auth.current() {
                Some(auth) => {
                    let step = auth
                        .submit_two_factor(code.expose())
                        .map_err(services::api_error_to_rpc)?;
                    Ok(RequestResult::LoginStep {
                        step: services::login_step_to_wire(step),
                    })
                }
                None => Err(no_engine_installed()),
            },
            Request::SubmitFidoPayload {
                client_data,
                authenticator_data,
                signature,
                credential_id,
            } => match self.services.auth.current() {
                Some(auth) => {
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
                }
                None => Err(no_engine_installed()),
            },
            Request::RefreshSession => match self.services.auth.current() {
                Some(auth) => {
                    let status = auth.refresh().map_err(services::api_error_to_rpc)?;
                    Ok(RequestResult::LoginStatus {
                        status: services::login_status_to_wire(status),
                    })
                }
                None => Err(no_engine_installed()),
            },
            Request::Logout => match self.services.auth.current() {
                Some(auth) => {
                    // FR-4: best-effort remote teardown, guaranteed
                    // local credential removal (Muon's logout is
                    // infallible by design; a transport failure is
                    // reported but the local state is the adapter's).
                    auth.logout().map_err(services::api_error_to_rpc)?;
                    Ok(RequestResult::Acknowledged)
                }
                None => Err(no_engine_installed()),
            },
            other => self.core.handle_request(ctx.peer.uid, other),
        }
    }

    fn event_bus(&self) -> &EventBus {
        &self.bus
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
    fn handler() -> (DaemonHandler, Arc<AtomicBool>) {
        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-handler-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = ConfigPaths::rooted(&dir);
        let services = Arc::new(
            DaemonServices::build_with_trust_root(&SystemConfig::default(), &paths, &dir)
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
