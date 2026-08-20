//! The Muon authentication adapter (M2 S4, T-15): `AuthenticationApi`
//! over the pinned Muon 2.6.1 client.
//!
//! State-machine mapping (spike memo Q1): Muon's login is a three-variant
//! `LoginFlow`; the adapter keeps the session between calls and re-enters
//! the 2FA stage through `AuthFlow::from_totp`/`from_fido` — the same
//! resume path `pvpnclient` uses — so no Muon flow object outlives a
//! trait call. Fail-closed rules:
//!
//! * ER-17: the engine client is built with `RetryPolicy::never()` — no
//!   automatic retries anywhere in the auth family; Muon's internal
//!   401-refresh-and-resend is session maintenance, not a retry, and
//!   stays. Visible retry policy is S7's scheduler, never this layer.
//! * Recovery codes have NO upstream arm (spike memo Q1's contradiction:
//!   `tfa::Post` has exactly `TwoFactorCode` and `FIDO2`), so a
//!   non-TOTP-shaped second factor is refused with the stable
//!   `unsupported-challenge` code before any wire action (FR-7L).
//! * A `twofactor`-scoped challenge offering neither TOTP nor FIDO2 is
//!   equally un-continuable: `LoginStep::Blocked` with
//!   [`BlockedReason::UnsupportedChallenge`].
//! * Human verification, organization SSO, guest login, and feedback
//!   have no authorized public Muon surface (spike memo Q1) — they stay
//!   the stable `blocked-upstream` refusals carried by
//!   [`BlockedReason`] for the S9 client surfaces; this adapter has no
//!   method that could reach them.
//!
//! Peer-secret front door (S1's finding-10 gate, enforced here): every
//! credential-shaped value arriving through this trait — username,
//! password, TOTP code, FIDO2 assertion fields, and imported fork
//! selectors — crosses the wire boundary into
//! [`protonwire_core::redact::peer_secret`] storage and is consumed via
//! `expose()`. The adapter never calls `register_secret` or
//! `SecretString::new` on wire input; the global scrub registry stays
//! local-provenance-only. The one registry registration it performs is
//! the fork selector *it mints* (local provenance — our own secret, so
//! the value scrubs if anything ever formats it).
//!
//! Session persistence: the adapter observes Muon's session state
//! through [`MemorySessionStore`] (Muon's `Store` contract is
//! deliberately synchronous and infallible — spike memo Q2); the durable
//! versioned envelope (`protonwire_store::session`, FR-7C) wraps the
//! serialized credentials and is written by the S5 persistence facade,
//! not by Muon's fire-and-forget hook.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use muon::Client;
use muon::auth::ForkFlowResult;
use muon::auth::LoginFlow;
use muon::auth::WithSelectorFlow;
use muon::common::Context;
use muon::sessions::Session;
use muon::sessions::SessionCredentials;
use muon::store::Store;
use protonwire_core::redact::peer_secret;
use protonwire_core::redact::register_secret;

use crate::ApiError;
use crate::AuthenticationApi;
use crate::BlockedReason;
use crate::Challenge;
use crate::Fido2Challenge;
use crate::Fido2Payload;
use crate::ForkSelector;
use crate::LoginStatus;
use crate::LoginStep;
use crate::SessionInfo;
use crate::runtime::EngineBridge;
use crate::runtime::TokioBridge;
use crate::runtime::TokioOs;
use crate::runtime::TokioSpawner;
use crate::runtime::os_prng;

/// Every string-keyed Muon store can answer "which auth does this key
/// hold" through the trait's bulk read — the adapter's observation
/// without an inherent-method bound on `S`.
trait SessionStoreView {
    fn current_auth(&self, key: &str) -> muon::auth::Auth;
}

impl<S: Store<Key = String>> SessionStoreView for S {
    fn current_auth(&self, key: &str) -> muon::auth::Auth {
        self.get_all_auth()
            .get(key)
            .cloned()
            .unwrap_or(muon::auth::Auth::None)
    }
}

/// The concrete Muon context the adapter builds: the tokio-backed hyper
/// transport, an injected session store, an injected information
/// provider, and no cookie store (cookie persistence rides the S4/S5
/// store decision — spike memo "Adapter-facing facts").
pub type AdapterContext<S, IP> = muon::common::GenericContext<
    muon::http::hyper::connector::HyperConnector<TokioOs, muon::rt::SendExecutor<TokioSpawner>>,
    S,
    IP,
>;

// ---------------------------------------------------------------------------
// The observation store
// ---------------------------------------------------------------------------

/// A minimal in-memory Muon `Store` (the spike memo's minimal store for
/// driving the real auth code paths): Muon's preload contract reads
/// everything once at construction, writes are fire-and-forget, and the
/// adapter reads back what Muon stored to derive login status and
/// post-import session identity (Muon hands no `LoginFlowData` on the
/// fork-import path).
///
/// Clone shares one map, so the adapter's observation handle and Muon's
/// persistence view are the same storage. `Auth::Anonymous` entries are
/// expected (Muon mints anonymous API sessions on first send) and are
/// not logins.
#[derive(Debug, Clone, Default)]
pub struct MemorySessionStore {
    auths: Arc<Mutex<HashMap<String, muon::auth::Auth>>>,
}

impl MemorySessionStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The auth Muon currently holds for `key` (`Auth::None` when
    /// absent).
    pub fn get(&self, key: &str) -> muon::auth::Auth {
        self.auths
            .lock()
            .expect("session store lock")
            .get(key)
            .cloned()
            .unwrap_or(muon::auth::Auth::None)
    }
}

impl Store for MemorySessionStore {
    type Key = String;

    fn set_auth(&mut self, key: Self::Key, auth: muon::auth::Auth) {
        self.auths
            .lock()
            .expect("session store lock")
            .insert(key, auth);
    }

    fn remove_auth(&mut self, key: &Self::Key) {
        self.auths.lock().expect("session store lock").remove(key);
    }

    fn get_all_auth(&self) -> HashMap<Self::Key, muon::auth::Auth> {
        self.auths.lock().expect("session store lock").clone()
    }
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/// The post-`begin_login` 2FA state the adapter keeps between calls.
struct PendingTwoFactor {
    /// The identity Muon reported at login (returned by the completion
    /// arms — Muon's 2FA submission hands back only the session).
    info: SessionInfo,
    /// The reduced challenge handed to the client.
    challenge: Challenge,
    /// Muon's full FIDO2 challenge, kept to reconstruct the
    /// `authentication_options` the assertion must be submitted with
    /// (the reduced [`Fido2Challenge`] is deliberately lossy).
    fido2: Option<muon::rest::auth::v4::fido2::Response>,
}

/// The live adapter state: the session handle, any pending 2FA
/// continuation, and the scrub-registry guards for fork selectors this
/// adapter minted (local-provenance secrets stay registered for as long
/// as the adapter — and thereby the values — live).
struct AuthState<C: Context> {
    session: Session<C>,
    pending: Option<PendingTwoFactor>,
    fork_scrub_guards: Vec<protonwire_core::redact::SecretHandle>,
}

/// `AuthenticationApi` over a real Muon client.
///
/// Generic over the engine bridge ([`EngineBridge`], the sync→async
/// seam), the session store, and the information provider, with a
/// production constructor ([`MuonAuth::connect`]) fixing the defaults.
pub struct MuonAuth<B = TokioBridge, S = MemorySessionStore, IP = muon::NoInfo>
where
    B: EngineBridge,
    S: Store<Key = String> + Clone + Send + Sync + 'static,
    IP: muon::ProvideInformation + Send + Sync + 'static,
{
    bridge: B,
    client: Client<AdapterContext<S, IP>>,
    store: S,
    key: String,
    state: Mutex<AuthState<AdapterContext<S, IP>>>,
}

impl MuonAuth {
    /// The production constructor: a dedicated engine runtime
    /// ([`TokioBridge`]), an empty in-memory session store, no
    /// fingerprint information.
    ///
    /// `store` preload note (FR-7JB): a durable store must complete its
    /// read before it is handed here — Muon reads it once, synchronously,
    /// at client construction. For the in-memory default there is
    /// nothing to preload.
    ///
    /// # Errors
    /// Runtime construction, PRNG seeding, SDK identity, or the Muon
    /// client build failed — mapped onto [`ApiError::Transport`].
    pub fn connect(
        app: muon::App,
        env: muon::Environment,
        session_key: impl Into<String>,
    ) -> Result<Self, ApiError> {
        let bridge = TokioBridge::dedicated()
            .map_err(|e| ApiError::Transport(format!("engine runtime: {e}")))?;
        Self::build(
            app,
            env,
            session_key.into(),
            bridge,
            MemorySessionStore::new(),
            muon::NoInfo,
        )
    }
}

impl<B, S, IP> MuonAuth<B, S, IP>
where
    B: EngineBridge,
    S: Store<Key = String> + Clone + Send + Sync + 'static,
    IP: muon::ProvideInformation + Send + Sync + 'static,
    muon::Session<AdapterContext<S, IP>>: Send + Sync + 'static,
    Client<AdapterContext<S, IP>>: Send + Sync,
{
    /// Builds the adapter over injected parts: the engine bridge, the
    /// (preloaded) session store, and the information provider Muon asks
    /// for anti-abuse fingerprints.
    ///
    /// # Errors
    /// PRNG seeding, SDK identity, the Muon client build, or session
    /// creation failed — mapped onto [`ApiError::Transport`].
    pub fn build(
        app: muon::App,
        env: muon::Environment,
        session_key: String,
        bridge: B,
        store: S,
        info_provider: IP,
    ) -> Result<Self, ApiError> {
        // ER-17: RetryPolicy::never() — the auth family never auto-retries.
        let retry = muon::common::RetryPolicy::default().never();
        let sdk = muon::common::sdk::Sdk::new("protonwire", env!("CARGO_PKG_VERSION"))
            .map_err(|e| ApiError::Transport(format!("sdk identity: {e}")))?;
        let os_prng = os_prng().map_err(|e| ApiError::Transport(format!("entropy: {e}")))?;
        let store_view = store.clone();
        let key_for_session = session_key.clone();

        let client = bridge
            .block_on(Box::pin(async move {
                muon::Client::builder(app, env)
                    .with_operating_system(TokioOs::default(), os_prng)
                    .with_multi_thread_executor(TokioSpawner)
                    .retry_policy(retry)
                    .with_persistence(store_view)
                    .with_info_provider(info_provider)
                    .without_cookie_store()
                    .register_sdk(sdk)
                    .build()
            }))
            .map_err(muon_err)?;

        // Resume when the (preloaded) store already holds this key's
        // session, mint a fresh one otherwise (FR-7JB resume path).
        let existing = store.current_auth(&session_key);
        let client_for_session = client.clone();
        let session = if matches!(
            existing,
            muon::auth::Auth::Internal { .. } | muon::auth::Auth::External { .. }
        ) {
            bridge
                .block_on(Box::pin(async move {
                    client_for_session.get_session(key_for_session).await
                }))
                .ok_or_else(|| ApiError::Transport("stored session vanished".into()))?
        } else {
            bridge
                .block_on(Box::pin(async move {
                    client_for_session
                        .new_session_without_credentials(key_for_session)
                        .await
                }))
                .map_err(muon_err)?
        };

        Ok(Self {
            bridge,
            client,
            store,
            key: session_key,
            state: Mutex::new(AuthState {
                session,
                pending: None,
                fork_scrub_guards: Vec::new(),
            }),
        })
    }

    /// The underlying Muon client (for engine-level callers such as the
    /// S6 catalog session and the canary suite).
    #[must_use]
    pub fn client(&self) -> &Client<AdapterContext<S, IP>> {
        &self.client
    }

    /// The adapter's observation of the auth Muon holds for the session
    /// key.
    pub fn observed_auth(&self) -> muon::auth::Auth {
        self.store.current_auth(&self.key)
    }

    /// The observed auth as Muon `SessionCredentials` — exactly the
    /// value the FR-7C envelope persists (`protonwire_store::session`
    /// wraps its serialization verbatim). `None` when the session is
    /// anonymous or absent.
    #[must_use]
    pub fn observed_credentials(&self) -> Option<SessionCredentials> {
        self.observed_auth().try_into().ok()
    }

    /// The session, cloning the shared handle.
    fn session(&self, state: &AuthState<AdapterContext<S, IP>>) -> Session<AdapterContext<S, IP>> {
        state.session.clone()
    }
}

/// Login status from the observed auth shape (no wire call — Muon's own
/// `is_authenticated` is store-local too).
fn status_of(auth: &muon::auth::Auth) -> LoginStatus {
    use muon::auth::Auth;
    use muon::auth::Tokens;
    match auth {
        Auth::Internal {
            tok: Tokens::Access { .. },
            ..
        } => LoginStatus::LoggedIn,
        Auth::Internal {
            tok: Tokens::Refresh { .. },
            ..
        } => LoginStatus::NeedsRefresh,
        Auth::External { .. } | Auth::Anonymous { .. } | Auth::None => LoginStatus::LoggedOut,
    }
}

/// `SessionInfo` from an observed internal auth (the fork-import path:
/// Muon reports no `LoginFlowData` there, but the store observed the
/// identity Muon persisted).
fn info_of(auth: &muon::auth::Auth) -> Option<SessionInfo> {
    match auth {
        muon::auth::Auth::Internal { user_id, uid, .. } => Some(SessionInfo {
            user_id: user_id.clone(),
            session_id: uid.clone(),
        }),
        _ => None,
    }
}

/// The reduced client-facing challenge from Muon's 2FA flags.
fn challenge_from(totp: bool, fido: &Option<muon::rest::auth::v4::fido2::Response>) -> Challenge {
    let fido2 = fido.as_ref().and_then(|response| {
        response
            .authentication_options
            .as_ref()
            .map(|options| Fido2Challenge {
                challenge: options.public_key.challenge.clone(),
                allow_credentials: options
                    .public_key
                    .allow_credentials
                    .as_ref()
                    .map(|list| {
                        list.iter()
                            .map(|descriptor| descriptor.id.clone())
                            .collect()
                    })
                    .unwrap_or_default(),
            })
    });
    Challenge {
        totp_enabled: totp,
        fido2,
    }
}

/// A TOTP is 6–8 ASCII digits. Anything else — a recovery code's
/// dashed alphanumeric shape above all — has no upstream submission arm
/// (spike memo Q1) and must never be sent as a `TwoFactorCode`.
fn is_totp_shape(code: &str) -> bool {
    (6..=8).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_digit())
}

/// Maps a Muon engine error onto the adapter taxonomy (transport class,
/// upstream detail preserved in the message).
fn muon_err(err: muon::Error) -> ApiError {
    ApiError::Transport(format!("muon engine failure: {err}"))
}

/// Maps a Muon flow error onto the adapter taxonomy. The stable refusal
/// codes live at the arms that produce them; everything upstream reports
/// (transport, status, SRP) is transport-class with the upstream detail
/// preserved in the message.
fn flow_error(err: impl std::fmt::Display) -> ApiError {
    ApiError::Transport(format!("muon auth flow failure: {err}"))
}

impl<B, S, IP> AuthenticationApi for MuonAuth<B, S, IP>
where
    B: EngineBridge,
    S: Store<Key = String> + Clone + Send + Sync + 'static,
    IP: muon::ProvideInformation + Send + Sync + 'static,
    muon::Session<AdapterContext<S, IP>>: Send + Sync + 'static,
    Client<AdapterContext<S, IP>>: Send + Sync,
{
    fn login_status(&self) -> Result<LoginStatus, ApiError> {
        Ok(status_of(&self.observed_auth()))
    }

    fn begin_login(&self, username: &str, password: &str) -> Result<LoginStep, ApiError> {
        // Peer-secret front door: wire-supplied credentials live in
        // zeroizing, unregistered storage for exactly this call.
        let username = peer_secret(username.to_owned());
        let password = peer_secret(password.to_owned());

        let mut state = self.state.lock().expect("adapter state lock");
        let session = self.session(&state);
        let flow = self.bridge.block_on(Box::pin(async move {
            session
                .auth()
                .login(username.expose(), password.expose())
                .await
        }));
        match flow {
            LoginFlow::Ok(session, data) => {
                state.session = session;
                state.pending = None;
                Ok(LoginStep::Session(SessionInfo {
                    user_id: data.user_id,
                    session_id: data.session_id,
                }))
            }
            LoginFlow::TwoFactor(two_factor, data) => {
                // The flow object is consumed for its flags and dropped:
                // the partial auth is in the store, and submission
                // re-enters through from_totp/from_fido on the retained
                // session handle (the resume path pvpnclient uses).
                let info = SessionInfo {
                    user_id: data.user_id,
                    session_id: data.session_id,
                };
                let fido2 = two_factor.fido_details().cloned();
                let challenge = challenge_from(two_factor.has_totp(), &fido2);
                if !challenge.totp_enabled && challenge.fido2.is_none() {
                    // Fail-closed: a twofactor-scoped challenge offering
                    // no submittable arm cannot be continued by pinned
                    // Muon — never guess, never auto-retry (ER-17).
                    state.pending = None;
                    return Ok(LoginStep::Blocked(BlockedReason::UnsupportedChallenge));
                }
                state.pending = Some(PendingTwoFactor {
                    info,
                    challenge,
                    fido2,
                });
                Ok(LoginStep::Challenge(
                    state
                        .pending
                        .as_ref()
                        .expect("just stored")
                        .challenge
                        .clone(),
                ))
            }
            LoginFlow::Failed { reason, .. } => Err(flow_error(reason)),
        }
    }

    fn submit_two_factor(&self, code: &str) -> Result<LoginStep, ApiError> {
        // Fail-closed before any wire action: recovery codes (and every
        // other non-TOTP shape) have no upstream arm (spike memo Q1).
        if !is_totp_shape(code) {
            return Err(ApiError::UnsupportedChallenge("recovery-code"));
        }
        let code = peer_secret(code.to_owned());

        let mut state = self.state.lock().expect("adapter state lock");
        let pending = state
            .pending
            .take()
            .ok_or(ApiError::InvalidState("no 2FA challenge in progress"))?;
        if !pending.challenge.totp_enabled {
            state.pending = Some(pending);
            return Err(ApiError::UnsupportedChallenge("totp-not-offered"));
        }
        let info = pending.info.clone();
        let session = self.session(&state);
        let result = self.bridge.block_on(Box::pin(async move {
            session.auth().from_totp(code.expose()).await
        }));
        match result {
            Ok(session) => {
                state.session = session;
                state.pending = None;
                Ok(LoginStep::Session(info))
            }
            Err(err) => {
                // The partial auth survives in the store; a corrected
                // code may be resubmitted against the same challenge.
                state.pending = Some(pending);
                Err(flow_error(err))
            }
        }
    }

    fn submit_fido_payload(&self, payload: &Fido2Payload) -> Result<LoginStep, ApiError> {
        // Peer-secret front door: the assertion fields are the peer's
        // ceremony output.
        let client_data = peer_secret(payload.client_data.clone());
        let authenticator_data = peer_secret(payload.authenticator_data.clone());
        let signature = peer_secret(payload.signature.clone());

        let mut state = self.state.lock().expect("adapter state lock");
        let pending = state
            .pending
            .take()
            .ok_or(ApiError::InvalidState("no 2FA challenge in progress"))?;
        let Some(fido2) = pending.fido2.as_ref() else {
            state.pending = Some(pending);
            return Err(ApiError::UnsupportedChallenge("fido2-not-offered"));
        };
        let Some(options) = fido2.authentication_options.clone() else {
            state.pending = Some(pending);
            return Err(ApiError::UnsupportedChallenge("fido2-not-offered"));
        };
        let info = pending.info.clone();
        let request = muon::rest::auth::v4::fido2::Request {
            authentication_options: options,
            client_data: client_data.expose().to_owned(),
            authenticator_data: authenticator_data.expose().to_owned(),
            signature: signature.expose().to_owned(),
            credential_id: payload.credential_id.clone(),
        };
        let session = self.session(&state);
        let result =
            self.bridge.block_on(Box::pin(
                async move { session.auth().from_fido(request).await },
            ));
        match result {
            Ok(session) => {
                state.session = session;
                state.pending = None;
                Ok(LoginStep::Session(info))
            }
            Err(err) => {
                // Keep the full FIDO2 challenge: a corrected assertion
                // may be resubmitted against it.
                state.pending = Some(pending);
                Err(flow_error(err))
            }
        }
    }

    fn refresh(&self) -> Result<LoginStatus, ApiError> {
        let mut state = self.state.lock().expect("adapter state lock");
        // A forced refresh invalidates any pending 2FA challenge (qa
        // P2, S4 round): the challenge was minted against pre-refresh
        // session material, and submitting it afterwards would drive
        // the wire with stale challenge state — transport-class
        // nonsense. Fail closed: the stale submit becomes an
        // `InvalidState` refusal before any wire action (the rust/qa
        // convergent decision; the client surfaces orchestrate the
        // login → submit ordering).
        state.pending = None;
        let session = self.session(&state);
        self.bridge
            .block_on(Box::pin(async move { session.refresh_auth().await }))
            .map_err(flow_error)?;
        drop(state);
        Ok(status_of(&self.observed_auth()))
    }

    fn logout(&self) -> Result<(), ApiError> {
        let mut state = self.state.lock().expect("adapter state lock");
        let session = self.session(&state);
        // Muon's logout is infallible by design: best-effort remote
        // DELETE, local state always cleared (spike memo). The remote
        // outcome is not an error the caller can act on.
        self.bridge.block_on(Box::pin(async move {
            session.logout().await;
        }));
        state.pending = None;
        Ok(())
    }

    fn fork(&self, child_id: &str) -> Result<ForkSelector, ApiError> {
        let mut state = self.state.lock().expect("adapter state lock");
        match status_of(&self.observed_auth()) {
            LoginStatus::LoggedIn | LoginStatus::NeedsRefresh => {}
            LoginStatus::LoggedOut => return Err(ApiError::InvalidState("not logged in")),
        }
        let session = self.session(&state);
        let child_id = child_id.to_owned();
        let result = self
            .bridge
            .block_on(Box::pin(async move { session.fork(child_id).send().await }));
        match result {
            ForkFlowResult::Success(_, selector) => {
                // Local provenance: our own minted secret, registered so
                // the value scrubs if anything ever formats it (FR-7P
                // layering). The peer-derived inputs above never get
                // this treatment; the guard lives as long as the
                // adapter, matching the selector's lifetime.
                state.fork_scrub_guards.push(register_secret(&selector));
                Ok(ForkSelector::new(selector))
            }
            ForkFlowResult::Failure { reason, .. } => Err(flow_error(reason)),
        }
    }

    fn import_fork(&self, selector: &ForkSelector) -> Result<LoginStep, ApiError> {
        // Peer-secret front door: an imported selector is a
        // session-bearing secret that arrived from outside.
        let selector = peer_secret(selector.as_str().to_owned());

        let mut state = self.state.lock().expect("adapter state lock");
        if let muon::auth::Auth::Internal { .. } | muon::auth::Auth::External { .. } =
            self.observed_auth()
        {
            return Err(ApiError::InvalidState(
                "session active; logout before importing",
            ));
        }
        let session = self.session(&state);
        let selector_value = selector.expose().to_owned();
        let result = self.bridge.block_on(Box::pin(async move {
            session
                .auth()
                .from_fork()
                .with_selector(selector_value)
                .await
        }));
        match result {
            WithSelectorFlow::Ok(session, _payload) => {
                state.session = session;
                state.pending = None;
                let auth = self.observed_auth();
                match info_of(&auth) {
                    Some(info) => Ok(LoginStep::Session(info)),
                    None => Err(ApiError::Transport(
                        "fork import stored no internal auth".into(),
                    )),
                }
            }
            WithSelectorFlow::Failed { reason, .. } => Err(flow_error(reason)),
        }
    }
}
