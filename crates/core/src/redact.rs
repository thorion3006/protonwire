//! Secret redaction for logs (PRD FR-121, FR-7P, T-10, T-32).
//!
//! Three defenses, layered (FR-7P: value scrubbing alone is not a
//! sufficient control):
//!
//! 1. [`SecretString`] / [`PeerSecret`] — zeroizing wrappers whose
//!    `Debug`/`Display` render as `[redacted]`, so accidental formatting
//!    never leaks the value.
//! 2. [`RedactingMakeWriter`] — a `tracing-subscriber` writer that scrubs
//!    registered secret *values* from every emitted line, including values
//!    that dependencies stringify into messages (the Muon/ProTUN leak path
//!    called out by FR-7P). The registry behind it is lifetime-tracked and
//!    writable only from local provenance — peer-derived values are
//!    refused by construction ([`peer_secret`], M1 security finding 10).
//! 3. [`SecretSuppressFilter`] — a per-layer filter that drops events
//!    from the named dependency modules *before formatting* (FR-7P:
//!    muon's auth subtree logs the TOTP code, username, and fork selector
//!    at `info`; pvpnclient traces fork selectors and the cookie jar).
//!    A message that is never formatted cannot leak, not even in a
//!    derived form the value scrubber would miss.
//!
//! The [`canary`] module is the T-32 harness: parameterized over a
//! [`canary::CanaryEmitter`], it injects every secret class through the
//! production stack and asserts nothing reaches any captured writer at
//! any allowed runtime level.
//!
//! Registered values are tracked by lifetime: an ALIVE secret is always
//! scrubbable and dead ones fall out of the registry (no count cap can age
//! a live token out of scrubbing — Codex PR review finding 12), and every
//! value is zeroized when its last handle drops.

use std::borrow::Cow;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use tracing::Level;
use zeroize::Zeroizing;

/// Placeholder substituted for secret values.
pub const REDACTED: &str = "[redacted]";

/// Minimum length for a registrable secret; shorter strings scrub too
/// aggressively (for example a 2-char fragment would mangle ordinary words).
const MIN_SECRET_LEN: usize = 4;

/// Lifetime-aware registry: weak references to the secret values, so a
/// value is scrubbable exactly as long as at least one handle (a
/// [`SecretString`] or [`SecretHandle`]) keeps it alive.
static REGISTRY: Mutex<Vec<std::sync::Weak<Zeroizing<String>>>> = Mutex::new(Vec::new());

/// Prunes dead weak entries, then registers `value` and returns the strong
/// handle that keeps it scrubbable.
///
/// The one `to_owned` here is the unavoidable cost of the borrowed API; the
/// resulting allocation goes straight into zeroizing storage via
/// [`register_owned`].
fn register(value: &str) -> Arc<Zeroizing<String>> {
    register_owned(value.to_owned())
}

/// Registers an already-owned secret value, MOVING the caller's allocation
/// into zeroizing storage with no intermediate copy (pr-champion WO-2:
/// `register(&value.into())` used to strand an unzeroized temporary clone
/// of the secret next to the zeroizing copy).
fn register_owned(value: String) -> Arc<Zeroizing<String>> {
    let secret = Arc::new(Zeroizing::new(value));
    if secret.len() >= MIN_SECRET_LEN {
        let mut registry = REGISTRY.lock().expect("secret registry lock");
        registry.retain(|weak| weak.strong_count() > 0);
        registry.push(Arc::downgrade(&secret));
    }
    secret
}

/// Registers a secret value for scrubbing and returns the handle that
/// keeps it registered.
///
/// Dropping every handle to the value removes it from scrubbing — hold the
/// handle for exactly as long as the value may appear in logs. Prefer
/// [`SecretString`], which is its own handle.
#[must_use = "dropping the handle unregisters the secret; hold it for as long as the value may appear in logs"]
pub fn register_secret(value: &str) -> SecretHandle {
    SecretHandle(register(value))
}

/// Handle keeping one registered secret value scrubbable.
#[derive(Clone)]
pub struct SecretHandle(Arc<Zeroizing<String>>);

impl SecretHandle {
    /// Read access for the deliberate consumer.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// Replaces every occurrence of a registered (still alive) secret with
/// [`REDACTED`].
///
/// Secrets are replaced longest-first: when one secret is a substring of
/// another (a token embedded in a longer value), replacing the shorter one
/// first would leave the longer secret's residue in the output.
pub fn scrub(input: &str) -> Cow<'_, str> {
    let mut registry = REGISTRY.lock().expect("secret registry lock");
    registry.retain(|weak| weak.strong_count() > 0);
    let mut secrets: Vec<_> = registry.iter().filter_map(|weak| weak.upgrade()).collect();
    secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    let mut output: Option<String> = None;
    for secret in secrets {
        if input.contains(secret.as_str()) {
            let target = output.as_deref().unwrap_or(input);
            output = Some(target.replace(secret.as_str(), REDACTED));
        }
    }
    output.map(Cow::Owned).unwrap_or(Cow::Borrowed(input))
}

/// A zeroizing, redacting-on-format secret string.
///
/// The value is registered for log scrubbing for exactly the secret's
/// lifetime (clones share one registration).
#[derive(Clone)]
pub struct SecretString(Arc<Zeroizing<String>>);

impl SecretString {
    /// Creates a secret and registers its value for log scrubbing. The
    /// caller's allocation moves into zeroizing storage directly — no
    /// unzeroized copy is made along the way.
    pub fn new(value: impl Into<String>) -> Self {
        Self(register_owned(value.into()))
    }

    /// Read access for the deliberate consumer.
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

impl std::fmt::Display for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

/// A `tracing` writer factory whose writers scrub secrets line by line.
#[derive(Debug, Clone, Copy)]
pub struct RedactingMakeWriter<W> {
    inner: W,
}

impl<W> RedactingMakeWriter<W> {
    /// Wraps an inner writer factory (for example `std::io::stdout`).
    pub fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<'a, W: tracing_subscriber::fmt::MakeWriter<'a>> tracing_subscriber::fmt::MakeWriter<'a>
    for RedactingMakeWriter<W>
{
    type Writer = LineScrubWriter<W::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        LineScrubWriter {
            inner: self.inner.make_writer(),
            line: Vec::new(),
        }
    }
}

/// Buffers bytes until a newline, scrubs the finished line, then forwards it.
pub struct LineScrubWriter<W: Write> {
    inner: W,
    line: Vec<u8>,
}

impl<W: Write> Write for LineScrubWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.line.extend_from_slice(buf);
        while let Some(pos) = self.line.iter().position(|&b| b == b'\n') {
            let mut rest = self.line.split_off(pos + 1);
            self.flush_line()?;
            std::mem::swap(&mut self.line, &mut rest);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_line()?;
        self.inner.flush()
    }
}

impl<W: Write> LineScrubWriter<W> {
    fn flush_line(&mut self) -> io::Result<()> {
        if self.line.is_empty() {
            return Ok(());
        }
        let decoded = String::from_utf8_lossy(&self.line);
        let scrubbed = scrub(&decoded);
        self.inner.write_all(scrubbed.as_bytes())?;
        self.line.clear();
        Ok(())
    }
}

/// Initializes global tracing with redaction applied to stdout.
///
/// `RUST_LOG` filtering applies when `env_filter` is `true` (the production
/// default). The FR-7P suppression filter ([`SecretSuppressFilter`]) is
/// applied in both arms.
pub fn init_tracing(env_filter: bool) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    if env_filter {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        tracing_subscriber::registry()
            .with(suppressed_fmt_layer(std::io::stdout, true))
            .with(filter)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(suppressed_fmt_layer(std::io::stdout, true))
            .init();
    }
}

/// Initializes global tracing with redaction and a caller-supplied default
/// level that applies when `RUST_LOG` is unset.
///
/// Events from the dependency modules named by FR-7P are dropped before
/// formatting at EVERY runtime level — a `RUST_LOG=trace` debugging
/// session must not re-open the credential-carrying modules.
pub fn init_tracing_filtered(default_level: &str) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    tracing_subscriber::registry()
        .with(suppressed_fmt_layer(std::io::stdout, true))
        .with(filter)
        .init();
}

// ---------------------------------------------------------------------------
// FR-7P before-formatting suppression
// ---------------------------------------------------------------------------

/// Per-module secret suppression, applied BEFORE formatting (FR-7P).
///
/// A `tracing-subscriber` per-layer
/// [`Filter`](tracing_subscriber::layer::Filter) that drops — never
/// formats — events from the pinned dependency modules at the levels
/// where those modules are known to log secrets. It composes over the
/// [`RedactingMakeWriter`] formatter via
/// [`suppressed_fmt_layer`]/`init_tracing_filtered`: `EnvFilter` decides
/// what the runtime level allows, this filter independently vetoes the
/// named modules regardless of that level, and only what survives both
/// reaches the (still scrubbing) writer. A message that is never
/// formatted cannot leak, not even in a derived form (a `:#?`
/// pretty-print, a re-encoded fragment) that value scrubbing would miss —
/// which is why FR-7P calls post-processing insufficient as the sole
/// control.
///
/// The named caps apply in every build at every runtime level; the
/// dependency-wide `trace` ban applies in release builds only
/// (FR-121), so debug sessions can still ask dependencies for detail
/// outside the named modules.
#[derive(Debug, Clone, Copy)]
pub struct SecretSuppressFilter {
    /// Whether the release-build blanket rule (dependency `trace` off)
    /// is active.
    release: bool,
}

/// The per-module suppression table (FR-7P, verified and extended by the
/// S0 spike — `docs/spike-2026-08.md` Q9, commit 029b492). Entries cap a
/// dependency module at the level named: events more verbose than the
/// cap — the levels where that module logs FR-121-forbidden values — are
/// dropped before formatting in every build at every runtime level.
///
/// muon 2.6.1 has FIVE info-level disclosure sites beyond the PRD's
/// TOTP claim (all confirmed against the pinned sources):
///
/// - `muon::auth::login` — TOTP code formatted into the message body
///   (`login.rs:271` feeding the `info!` at `:244`), username via Display
///   (`:66`), SRP session id (`:82`, `:86`), UID fields (`:115-157`),
///   `%auth` Display (`:262`).
/// - `muon::auth::from_fork` — the fork selector, twice (`:54`, `:156`),
///   UID fields, `%auth` (`:82`, `:187`).
/// - `muon::store` — `Auth` Debug output carrying user_id + UID
///   (`store.rs:206`, `:215`; token values are redacted upstream, the
///   IDs are not).
/// - `muon::common::auth` — UID fields throughout, and the device
///   fingerprint: `"setting fingerprint {fingerprint}"` (`:351`).
/// - `muon::client` — session keys (`client/mod.rs:621`).
///
/// pvpnclient 3.0.3 traces the fork selector and the whole cookie jar
/// (`supervisor/localagent.rs:422`); the cap is at crate granularity
/// because the leaking module sits behind a private `mod pvpnclient`
/// (full target `pvpnclient::pvpnclient::supervisor::localagent`),
/// brittle to name exactly.
///
/// A sixth muon site, found by S4's real-muon canary arm (absent from
/// the S0 memo's Q9 table — the arm exists precisely to catch what
/// source-reading misses):
///
/// - `muon::transport` — the WHOLE subtree, capped at ERROR.
///   `transport::http::req` logs the complete request at WARN with the
///   fork selector riding the PATH (`GET /auth/v4/sessions/forks/{selector}`),
///   and `transport::http::hyper::sender` plus its http1 sibling log
///   full request objects INCLUDING bodies at DEBUG/trace — every
///   credential that travels a body (username, TOTP, FIDO assertions,
///   refresh tokens, the fingerprint payload). Paths and bodies carry
///   secrets at every level below ERROR, and neither is coverable by
///   value scrubbing (peer-derived values must never enter the
///   registry), so before-formatting suppression is the only control;
///   the subtree's diagnostics are the price of closing the class.
const MODULE_CAPS: [(&str, Level); 7] = [
    ("muon::auth::login", Level::WARN),
    ("muon::auth::from_fork", Level::WARN),
    ("muon::store", Level::WARN),
    ("muon::common::auth", Level::WARN),
    ("muon::client", Level::WARN),
    ("muon::transport", Level::ERROR),
    ("pvpnclient", Level::DEBUG),
];

/// Release blanket (FR-121): targets outside this repository's own
/// crates (`protonwire*`) are capped at DEBUG — dependency `trace` is
/// off entirely in release builds.
const OWN_TARGET_PREFIX: &str = "protonwire";
const DEPENDENCY_RELEASE_CAP: Level = Level::DEBUG;

impl SecretSuppressFilter {
    /// The production FR-7P policy: the per-module caps of
    /// [`MODULE_CAPS`] always, plus the dependency-`trace`-off blanket
    /// in release builds.
    #[must_use]
    pub fn fr_7p() -> Self {
        Self::for_build(cfg!(not(debug_assertions)))
    }

    /// The same policy for an explicitly chosen build flavor — the seam
    /// the in-tree suite uses to test the release blanket from a debug
    /// build.
    #[must_use]
    pub fn for_build(release: bool) -> Self {
        Self { release }
    }

    /// True when this policy drops `metadata`'s event before formatting.
    #[must_use]
    pub fn suppresses(&self, metadata: &tracing::Metadata<'_>) -> bool {
        !self.allows(metadata.target(), metadata.level())
    }

    /// The decision core: is an event from `target` at `level` allowed
    /// through to the formatter?
    ///
    /// `tracing` levels order by verbosity (`TRACE > DEBUG > INFO >
    /// WARN > ERROR`), so "more verbose than the cap" — the side the cap
    /// exists to drop — is `level > cap`.
    fn allows(&self, target: &str, level: &Level) -> bool {
        if MODULE_CAPS
            .iter()
            .any(|(module, cap)| level > cap && target_matches(target, module))
        {
            return false;
        }
        if self.release && level > &DEPENDENCY_RELEASE_CAP && !target.starts_with(OWN_TARGET_PREFIX)
        {
            return false;
        }
        true
    }
}

/// Boundary-correct target-prefix match: `muon::auth::login` matches
/// that exact module and any submodule of it, but `muon::auth` never
/// matches a `muon_auth`-style sibling crate.
fn target_matches(target: &str, prefix: &str) -> bool {
    match target.strip_prefix(prefix) {
        Some(rest) => rest.is_empty() || rest.starts_with("::"),
        None => false,
    }
}

impl<S> tracing_subscriber::layer::Filter<S> for SecretSuppressFilter {
    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        _context: &tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        !self.suppresses(metadata)
    }
}

/// The redacting formatter under the FR-7P suppression filter — the one
/// per-layer composition every init path installs and the
/// [`canary`] harness runs emitters through, so the harness cannot drift
/// from production.
fn suppressed_fmt_layer<W>(
    writer: W,
    ansi: bool,
) -> impl tracing_subscriber::Layer<tracing_subscriber::registry::Registry> + Send + Sync + 'static
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    use tracing_subscriber::Layer as _;

    tracing_subscriber::fmt::layer()
        .with_ansi(ansi)
        .with_writer(RedactingMakeWriter::new(writer))
        .with_filter(SecretSuppressFilter::fr_7p())
}

// ---------------------------------------------------------------------------
// Peer-derived values: the registry guard (M1 security finding 10)
// ---------------------------------------------------------------------------

/// Zeroizing, redacting-on-format storage for a secret that arrived from
/// an IPC peer. Unlike [`SecretString`], a `PeerSecret` is never
/// registered in the global scrub registry — see [`peer_secret`].
#[derive(Clone)]
pub struct PeerSecret(Arc<Zeroizing<String>>);

impl PeerSecret {
    /// Wraps a peer-derived value in zeroizing, redacting-on-format
    /// storage without touching the scrub registry. Prefer the guard
    /// [`peer_secret`] at the wire boundary; this constructor exists for
    /// tests and non-IPC peer sources.
    #[must_use = "dropping the handle zeroizes the value; hold it for as long as the value is needed"]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Arc::new(Zeroizing::new(value.into())))
    }

    /// Read access for the deliberate consumer.
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for PeerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}
impl std::fmt::Display for PeerSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

/// THE registry guard the S4 wire path calls for every secret-shaped
/// value received over IPC (M1 security review finding 10, recorded as
/// a blocking requirement for M2): peer-derived values are refused entry
/// to the global scrub registry *by construction* — this function is the
/// sanctioned peer entry point, and no function exists that converts
/// peer input into a registration ([`register_secret`]/
/// [`SecretString::new`] stay local-provenance-only by convention, and a
/// `PeerSecret` cannot be turned into either).
///
/// Why the registry must stay local-only: it is a process-global
/// structure whose whole job is protecting this host's own secrets. A
/// writable-from-the-wire registry lets any local peer that can reach
/// the socket flood it with junk registrations — with the M1-era FIFO
/// cap that evicted real secrets from scrubbing; without a cap it is an
/// unbounded-memory lever. Peer values still get zeroizing storage and
/// `[redacted]` formatting; what they never get is a registry entry.
#[must_use = "dropping the handle zeroizes the value; hold it for as long as the value is needed"]
pub fn peer_secret(value: impl Into<String>) -> PeerSecret {
    PeerSecret::new(value)
}

// ---------------------------------------------------------------------------
// T-32 canary harness
// ---------------------------------------------------------------------------

/// The T-32 canary harness (m2-plan S1): inject canaries for every secret
/// class through a dependency-shaped [`CanaryEmitter`] and assert none
/// reaches any captured writer at any allowed runtime level.
///
/// Parameterized over the emitter so the stub arm (the pinned upstream
/// log sites, replayed) lands now while the real-muon arm rides with S4
/// in the same commit as the first real call sites — that arm drives
/// real muon with these values as live credentials through
/// [`assert_no_secrets_reach_logs`] unchanged.
pub mod canary {
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

    use super::suppressed_fmt_layer;

    /// Every allowed runtime log level (the `RUST_LOG` defaults the
    /// production stack accepts). The suite runs each emitter through
    /// all of them: suppression that only holds at `info` is no control.
    pub const ALLOWED_LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

    /// One unique, recognizable value per secret class in T-32's list,
    /// plus the UID/user_id class FR-121 names and the S0 memo adds
    /// (spike Q9: muon logs UID fields at `info` in five modules). Every
    /// value carries a shared run tag, so a leak in a failure message
    /// names its class and its run.
    pub struct Canaries {
        /// Shared per-run tag (also embedded in every value).
        pub run: String,
        pub password: String,
        pub totp: String,
        pub recovery_code: String,
        pub fido_payload: String,
        pub username: String,
        pub session_id: String,
        pub uid: String,
        pub selector: String,
        pub cookie: String,
        pub token: String,
        pub fingerprint: String,
        pub private_key: String,
    }

    impl Canaries {
        /// Generates a fresh set; safe across parallel tests (each call
        /// gets a distinct run tag).
        #[must_use]
        pub fn generate() -> Self {
            static RUNS: AtomicU64 = AtomicU64::new(0);
            let run = format!(
                "pwcanary-{}-{}",
                std::process::id(),
                RUNS.fetch_add(1, Ordering::Relaxed)
            );
            let value = |class: &str| format!("{run}/{class}");
            Self {
                password: value("password"),
                totp: value("totp"),
                recovery_code: value("recovery-code"),
                fido_payload: value("fido-payload"),
                username: value("username"),
                session_id: value("session-id"),
                uid: value("uid"),
                selector: value("selector"),
                cookie: value("cookie"),
                token: value("token"),
                fingerprint: value("fingerprint"),
                private_key: value("private-key"),
                run,
            }
        }

        /// Every `(class, value)` pair, for assertions.
        #[must_use]
        pub fn classes(&self) -> Vec<(&'static str, &str)> {
            vec![
                ("password", &self.password),
                ("totp", &self.totp),
                ("recovery_code", &self.recovery_code),
                ("fido_payload", &self.fido_payload),
                ("username", &self.username),
                ("session_id", &self.session_id),
                ("uid", &self.uid),
                ("selector", &self.selector),
                ("cookie", &self.cookie),
                ("token", &self.token),
                ("fingerprint", &self.fingerprint),
                ("private_key", &self.private_key),
            ]
        }
    }

    /// The seam the suite is parameterized over: emits the events the
    /// dependency under test would emit, against the currently-installed
    /// subscriber (the harness installs the production stack first).
    pub trait CanaryEmitter {
        /// Arm identity for failure messages (`"stub"` now; `"muon-2.6.1"`
        /// when the S4 arm lands).
        fn name(&self) -> &'static str;
        /// Emits the dependency's events, injecting every canary class.
        fn emit(&self, canaries: &Canaries);
    }

    /// The stub arm: replays the pinned upstream log sites from the S0
    /// memo's Q9 table — every module the suppression layer names, at the
    /// level that module leaks, with every T-32 class injected across the
    /// sites (worst case: a class upstream happens not to log today is
    /// still injected, so no class relies on upstream restraint).
    pub struct StubDependencyEmitter;

    impl CanaryEmitter for StubDependencyEmitter {
        fn name(&self) -> &'static str {
            "stub"
        }

        fn emit(&self, c: &Canaries) {
            // muon::auth::login at info — the verbatim TOTP shape
            // (login.rs:271 -> :244) plus username/session-id/UID fields
            // and the remaining adapter-supplied classes as fields.
            tracing::event!(
                target: "muon::auth::login",
                tracing::Level::INFO,
                username = %c.username,
                session_id = %c.session_id,
                uid = %c.uid,
                password = %c.password,
                recovery_code = %c.recovery_code,
                fido_payload = %c.fido_payload,
                token = %c.token,
                "sending TOTP request with code: {}", c.totp
            );
            // muon::auth::from_fork at info — the fork selector twice
            // (from_fork.rs:54, :156), cookies along for the ride.
            tracing::event!(
                target: "muon::auth::from_fork",
                tracing::Level::INFO,
                selector = %c.selector,
                cookie = %c.cookie,
                "acquiring forked session with selector {}", c.selector
            );
            // muon::store at info — Auth Debug (user_id + UID ride the
            // derived Debug form; store.rs:206, :215).
            tracing::event!(
                target: "muon::store",
                tracing::Level::INFO,
                "persisted auth state {:?}",
                (&c.uid, &c.username)
            );
            // muon::common::auth at info — the device fingerprint
            // (common/auth.rs:351) plus UID fields.
            tracing::event!(
                target: "muon::common::auth",
                tracing::Level::INFO,
                uid = %c.uid,
                "setting fingerprint {}", c.fingerprint
            );
            // muon::client at info — session keys (client/mod.rs:621).
            tracing::event!(
                target: "muon::client",
                tracing::Level::INFO,
                "registered session key {} for private key {}",
                c.session_id,
                c.private_key
            );
            // pvpnclient at trace — fork selector + the whole cookie jar
            // pretty-printed (localagent.rs:422).
            tracing::event!(
                target: "pvpnclient::pvpnclient::supervisor::localagent",
                tracing::Level::TRACE,
                "received fork selector {} and cookies {:#?}",
                c.selector,
                [c.cookie.as_str()]
            );
            // muon::transport::http::req at WARN — the whole request, the
            // fork selector riding the PATH (S4 real-muon canary finding;
            // absent from the S0 memo's Q9 table).
            tracing::event!(
                target: "muon::transport::http::req",
                tracing::Level::WARN,
                "is using the default time constraint self=GET /auth/v4/sessions/forks/{}",
                c.selector
            );
            // muon::transport::http::hyper::sender at DEBUG — full request
            // objects INCLUDING bodies: every credential class that
            // travels a request body.
            tracing::event!(
                target: "muon::transport::http::hyper::sender",
                tracing::Level::DEBUG,
                "sending request with hyper req=Request {{ .., body: Some(b\"{{\\\"Username\\\":\\\"{}\\\",\\\"TwoFactorCode\\\":\\\"{}\\\",\\\"ClientSecret\\\":\\\"{}\\\"}}\") }}",
                c.username,
                c.totp,
                c.fido_payload
            );
            // The http1 sibling at trace — same object shape.
            tracing::event!(
                target: "muon::transport::http::hyper::http1",
                tracing::Level::TRACE,
                "http1 send req=Request {{ .., body: Some(b\"{{\\\"RefreshToken\\\":\\\"{}\\\"}}\") }}",
                c.token
            );
        }
    }

    /// Distinctive fragments of the stubbed upstream messages. Even if
    /// every value were somehow scrubbed downstream, an unsuppressed
    /// event still formats its message — so these must never appear.
    /// This is the before-formatting property itself: the assertion a
    /// regex-post-processing "fix" cannot pass.
    const SUPPRESSED_EVENT_MARKERS: [&str; 9] = [
        "sending TOTP request with code",
        "acquiring forked session",
        "persisted auth state",
        "setting fingerprint",
        "registered session key",
        "received fork selector",
        "is using the default time constraint",
        "sending request with hyper",
        "http1 send req=",
    ];

    /// Runs `emitter` through the exact production stack (redacting
    /// formatter under the FR-7P suppression filter, `EnvFilter` at
    /// `level`) and asserts, for every secret class, that:
    ///
    /// 1. no canary value reaches the captured writer, and
    /// 2. no suppressed-module event is formatted at all.
    ///
    /// Panics naming the arm, the level, and the offending captured line.
    /// The stack is installed as the calling thread's default — no
    /// global subscriber is touched, so parallel tests are safe.
    ///
    /// # Panics
    /// On any canary value or suppressed-event marker in the capture.
    pub fn assert_no_secrets_reach_logs(emitter: &dyn CanaryEmitter) {
        for level in ALLOWED_LEVELS {
            let canaries = Canaries::generate();
            let captured = capture_at_level(level, &canaries, emitter);
            for (class, value) in canaries.classes() {
                assert!(
                    !captured.contains(value),
                    "[{}] canary class {class} reached the writer at \
                     RUST_LOG={level}:\n{captured}",
                    emitter.name()
                );
            }
            for marker in SUPPRESSED_EVENT_MARKERS {
                assert!(
                    !captured.contains(marker),
                    "[{}] a suppressed-module event was FORMATTED at \
                     RUST_LOG={level} (before-formatting suppression failed):\
                     \n{captured}",
                    emitter.name()
                );
            }
        }
    }

    /// In-order capture sink shared by every writer the fmt layer makes.
    #[derive(Clone, Default)]
    struct CaptureBuffer(Arc<Mutex<Vec<u8>>>);

    impl CaptureBuffer {
        fn string(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("capture lock")).into_owned()
        }
    }

    impl Write for CaptureBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("capture lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureBuffer {
        type Writer = CaptureBuffer;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Builds the production stack over a capture buffer (ANSI off for
    /// stable substring assertions), installs it as this thread's
    /// default, runs the emitter, and returns everything captured.
    fn capture_at_level(level: &str, canaries: &Canaries, emitter: &dyn CanaryEmitter) -> String {
        let buffer = CaptureBuffer::default();
        let subscriber = tracing_subscriber::registry()
            .with(suppressed_fmt_layer(buffer.clone(), false))
            .with(tracing_subscriber::EnvFilter::new(level));
        let _guard = tracing::subscriber::set_default(subscriber);
        emitter.emit(canaries);
        drop(_guard);
        buffer.string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Default)]
    struct SharedBuffer {
        data: std::sync::Arc<Mutex<Vec<u8>>>,
        writes: std::sync::Arc<AtomicUsize>,
    }

    impl SharedBuffer {
        fn string(&self) -> String {
            String::from_utf8_lossy(&self.data.lock().unwrap()).into_owned()
        }
    }

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.data.lock().unwrap().extend_from_slice(buf);
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
        type Writer = SharedBuffer;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn scrub_removes_registered_values() {
        let _keep = register_secret("hunter2supersecret");
        let out = scrub("login failed for hunter2supersecret at t=1");
        assert_eq!(out, "login failed for [redacted] at t=1");
    }

    #[test]
    fn secret_string_never_renders_its_value() {
        let secret = SecretString::new("tok_9f8e7d6c");
        assert_eq!(format!("{secret}"), REDACTED);
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(secret.expose(), "tok_9f8e7d6c");
        // ...and the value is scrubbed even when embedded via Display first.
        let embedded = format!("token={secret}");
        assert_eq!(scrub(&embedded), "token=[redacted]");
    }

    #[test]
    fn short_values_are_not_registered() {
        let _keep = register_secret("ab");
        assert_eq!(scrub("abc"), "abc");
    }

    /// Review finding: scrubbing in registration order lets a shorter
    /// secret that is a substring of a longer one partially consume the
    /// longer secret's text, disclosing its residue ("secret" leaking
    /// from "secretvalue"). Replacement must go longest-first.
    #[test]
    fn overlapping_secrets_redact_longest_first() {
        // Registration order short-then-long: replacement must go
        // longest-first regardless of the registry's incidental order.
        let _short = register_secret("value");
        let _long = register_secret("secretvalue");
        assert_eq!(scrub("x secretvalue y"), "x [redacted] y");

        // Reverse registration order (long-then-short): the arm above is
        // the one a plain `secrets.reverse()` in place of the
        // longest-first sort survives, because reversing registration
        // order happens to be long-first there. Registering the long
        // secret AFTER the short one makes reverse() scrub 'value' first
        // and leak the 'secret' residue — this arm pins the sort itself.
        let _long_again = register_secret("secretvalue");
        let _short_last = register_secret("value");
        assert_eq!(scrub("x secretvalue y"), "x [redacted] y");
    }

    #[test]
    fn writer_scrubs_full_lines() {
        let buffer = SharedBuffer::default();
        let mut writer = LineScrubWriter {
            inner: buffer.clone(),
            line: Vec::new(),
        };
        let _keep = register_secret("s3cr3t-value");
        writer
            .write_all(b"info: session s3cr3t-value accepted\nnext line\n")
            .unwrap();
        writer.flush().unwrap();
        let out = buffer.string();
        assert!(!out.contains("s3cr3t-value"), "leaked in: {out}");
        assert!(out.contains("[redacted]"));
    }

    #[test]
    fn writer_flushes_partial_line_on_flush() {
        let buffer = SharedBuffer::default();
        let mut writer = LineScrubWriter {
            inner: buffer.clone(),
            line: Vec::new(),
        };
        let _keep = register_secret("part-secret-99");
        writer.write_all(b"partial part-secret-99").unwrap();
        assert!(buffer.string().is_empty());
        writer.flush().unwrap();
        assert!(buffer.string().contains("[redacted]"));
    }
}

/// FR-7P policy unit tests for [`SecretSuppressFilter`]. The stack-level
/// behavior (events dropped before formatting at every allowed runtime
/// level) is pinned by the canary suite below; these pin the decision
/// table itself, target boundary included.
#[cfg(test)]
mod suppression_policy_tests {
    use super::*;

    #[test]
    fn muon_auth_login_is_capped_at_warn_in_every_build() {
        let debug_build = SecretSuppressFilter::for_build(false);
        // The leaking levels (S0 memo Q9): info and below.
        assert!(!debug_build.allows("muon::auth::login", &Level::INFO));
        assert!(!debug_build.allows("muon::auth::login", &Level::DEBUG));
        // The cap keeps diagnostics at warn and above.
        assert!(debug_build.allows("muon::auth::login", &Level::WARN));
        assert!(debug_build.allows("muon::auth::login", &Level::ERROR));
    }

    #[test]
    fn muon_from_fork_store_common_auth_client_are_capped_at_warn() {
        let f = SecretSuppressFilter::for_build(false);
        // from_fork: the fork selector at info (from_fork.rs:54, :156).
        assert!(!f.allows("muon::auth::from_fork", &Level::INFO));
        // store: Auth Debug with user_id + UID (store.rs:206, :215).
        assert!(!f.allows("muon::store", &Level::INFO));
        // common::auth: UID fields + device fingerprint (:351).
        assert!(!f.allows("muon::common::auth", &Level::INFO));
        // client: session keys (client/mod.rs:621) — including the
        // builder submodule.
        assert!(!f.allows("muon::client", &Level::INFO));
        assert!(!f.allows("muon::client::builder", &Level::INFO));
        // Every capped module keeps warn+.
        for module in [
            "muon::auth::from_fork",
            "muon::store",
            "muon::common::auth",
            "muon::client",
        ] {
            assert!(f.allows(module, &Level::WARN), "{module} keeps WARN");
        }
    }

    #[test]
    fn pvpnclient_is_capped_at_debug_in_every_build() {
        let f = SecretSuppressFilter::for_build(false);
        // The leaking module sits behind a private `mod pvpnclient`, so
        // the full target is doubly nested; the crate-level cap must
        // reach it, and trace must fall even at RUST_LOG=trace.
        assert!(!f.allows(
            "pvpnclient::pvpnclient::supervisor::localagent",
            &Level::TRACE
        ));
        // Debug survives: the cap drops exactly the leaking level.
        assert!(f.allows("pvpnclient::supervisor::localagent", &Level::DEBUG));
    }

    /// S4's real-muon canary arm found two transport-layer disclosure
    /// sites the S0 memo's Q9 table missed (see MODULE_CAPS): the fork
    /// selector rides the request PATH at WARN, and full request objects
    /// INCLUDING bodies are logged at DEBUG/trace. Paths and bodies carry
    /// credentials at every level below ERROR.
    #[test]
    fn muon_transport_subtree_is_capped_at_error_in_every_build() {
        let f = SecretSuppressFilter::for_build(false);
        // transport::http::req — the fork selector in the path at WARN.
        assert!(!f.allows("muon::transport::http::req", &Level::WARN));
        assert!(!f.allows("muon::transport::http::req", &Level::INFO));
        // hyper::sender logs bodies at DEBUG; the http1 sibling at trace.
        assert!(!f.allows("muon::transport::http::hyper::sender", &Level::DEBUG));
        assert!(!f.allows("muon::transport::http::hyper::http1", &Level::TRACE));
        // The subtree cap applies at the root and keeps ERROR only.
        assert!(!f.allows("muon::transport", &Level::WARN));
        assert!(f.allows("muon::transport", &Level::ERROR));
        assert!(f.allows("muon::transport::http::req", &Level::ERROR));
        // Boundary: near-name siblings keep their levels.
        assert!(f.allows("muon::transportx", &Level::TRACE));
        assert!(f.allows("muon::transporting::wire", &Level::DEBUG));
    }

    /// Target matching is boundary-correct: a cap on `muon::store` must
    /// not silence a `muon_store`-style sibling crate, and unrelated
    /// targets keep their levels (a filter that dropped everything would
    /// pass the canary suite trivially).
    #[test]
    fn caps_match_module_boundaries_and_leave_other_targets_alone() {
        let f = SecretSuppressFilter::for_build(false);
        assert!(f.allows("muon_rest::auth", &Level::INFO));
        assert!(f.allows("pvpnclientx::other", &Level::TRACE));
        // muon modules NOT in the table keep info (doh diagnostics).
        assert!(f.allows("muon::doh", &Level::INFO));
        // Own crates keep everything.
        assert!(f.allows("protonwire_core::state", &Level::TRACE));
    }

    /// FR-7P/FR-121: in release builds dependency `trace` is off
    /// ENTIRELY — not just for the named modules — while this repo's own
    /// crates keep whatever the runtime level allows. Debug builds leave
    /// non-named dependency verbosity to RUST_LOG.
    #[test]
    fn release_builds_disable_dependency_trace_entirely() {
        let release = SecretSuppressFilter::for_build(true);
        assert!(!release.allows("protun::tunnel", &Level::TRACE));
        assert!(!release.allows("muon::doh", &Level::TRACE));
        assert!(!release.allows("hyper::proto::h1", &Level::TRACE));
        // Trace off, debug stays.
        assert!(release.allows("protun::tunnel", &Level::DEBUG));
        // Own crates are exempt from the blanket.
        assert!(release.allows("protonwire_core::state", &Level::TRACE));
        // Debug builds: the blanket is inert outside MODULE_CAPS.
        let debug_build = SecretSuppressFilter::for_build(false);
        assert!(debug_build.allows("protun::tunnel", &Level::TRACE));
    }

    /// Characterization pin (green-by-design, S1 qa verdict): the
    /// production constructor wires the release blanket to the BUILD
    /// FLAVOR — `fr_7p()` carries exactly `cfg!(not(debug_assertions))`.
    /// The in-tree release-blanket tests drive `for_build(true)` as a
    /// seam, so nothing else fails if the production wiring drifts to
    /// never-apply (qa's M3b survivor); this line does.
    #[test]
    fn fr_7p_wires_the_release_blanket_to_the_build_flavor() {
        assert_eq!(
            SecretSuppressFilter::fr_7p().release,
            cfg!(not(debug_assertions))
        );
    }
}

/// The T-32 canary suite, stub arm (m2-plan S1). The real-muon arm rides
/// with S4 and reuses [`canary::assert_no_secrets_reach_logs`] unchanged.
#[cfg(test)]
mod canary_suite_tests {
    use super::canary::ALLOWED_LEVELS;
    use super::canary::assert_no_secrets_reach_logs;
    use super::canary::{Canaries, CanaryEmitter, StubDependencyEmitter};

    /// T-32: every secret class (password, TOTP/recovery code, FIDO
    /// payload, username, session ID, UID, selector, cookie, token,
    /// fingerprint, private key) injected through the pinned upstream
    /// log sites must reach NO captured writer at ANY allowed runtime
    /// level — and the suppressed modules' events must never be
    /// formatted at all (the before-formatting property).
    ///
    /// Red evidence (pre-fix, behavioral): the same two upstream shapes
    /// through the then-current stack — muon's
    /// `INFO muon::auth::login: sending TOTP request with code:
    /// pwcanary-totp-424242` at RUST_LOG=info and pvpnclient's
    /// `TRACE …localagent: received fork selector pwcanary-selector-7c7c7c
    /// and cookies ["pwcanary-cookie-9a9a9a9a9a"]` at RUST_LOG=trace —
    /// both reached the writer verbatim (run output in the commit
    /// message).
    #[test]
    fn t32_stub_arm_no_secret_class_reaches_any_writer() {
        assert_no_secrets_reach_logs(&StubDependencyEmitter);
    }

    /// Characterization pin (green-by-design, S1 qa verdict): the
    /// harness sweeps all FIVE allowed runtime levels. The green arm
    /// above cannot see a shrunk sweep (qa's M6 survivor — dropping
    /// levels from `ALLOWED_LEVELS` still passes it); this line pins
    /// the breadth itself.
    #[test]
    fn allowed_levels_sweep_all_five_runtime_levels() {
        assert_eq!(ALLOWED_LEVELS, ["error", "warn", "info", "debug", "trace"]);
    }

    /// QA mutation arm: an emitter leaking a canary through an
    /// UNSUPPRESSED module must be caught — otherwise the green above
    /// could be vacuous (a filter that dropped everything would pass it).
    struct LeakingControlEmitter;

    impl CanaryEmitter for LeakingControlEmitter {
        fn name(&self) -> &'static str {
            "leaking-control"
        }
        fn emit(&self, c: &Canaries) {
            tracing::event!(
                target: "protonwire_core::redact",
                tracing::Level::INFO,
                "control leak: {}", c.token
            );
        }
    }

    #[test]
    fn the_harness_itself_detects_a_leak() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_no_secrets_reach_logs(&LeakingControlEmitter);
        }));
        assert!(
            result.is_err(),
            "the harness must catch a control leak through an unsuppressed module"
        );
    }
}

/// The registry-poisoning guard (M1 security finding 10, blocking
/// requirement for M2).
#[cfg(test)]
mod peer_guard_tests {
    use super::*;

    /// Finding 10's scenario, killed by construction: a hostile IPC peer
    /// floods secret-shaped values through the wire path — none may enter
    /// the global scrub registry, and the registry this host's own
    /// secrets rely on must be untouched. Pre-fix this test is a
    /// disclosed compile-red (`peer_secret`/`PeerSecret` did not exist);
    /// the behavioral half — that a plain `register_secret` flood is
    /// merely survived (weak refs, no cap, finding 12) — is pinned in
    /// `registry_lifetime_tests` above.
    #[test]
    fn peer_derived_values_cannot_enter_the_scrub_registry() {
        // The protected asset: a locally-originated secret.
        let local = SecretString::new("tok-local-asset-under-protection");
        // The attack: junk "secrets" through the S4 wire path's guard.
        let flood: Vec<_> = (0..4096)
            .map(|i| peer_secret(format!("peer-junk-{i:06}")))
            .collect();
        // Refused by construction: the registry never saw any peer
        // value — each scrubs to itself, not to [redacted].
        for peer in flood.iter().step_by(256) {
            assert_eq!(
                scrub(peer.expose()),
                peer.expose(),
                "a peer-derived value must never be registered"
            );
        }
        // Unpoisoned: the local secret is exactly as scrubbable as
        // before the flood.
        assert_eq!(scrub(local.expose()), REDACTED);
        // And the peer value still cannot leak through formatting.
        assert_eq!(format!("{}", flood[0]), REDACTED);
        assert_eq!(format!("{:?}", flood[0]), REDACTED);
        assert_eq!(flood[0].expose(), "peer-junk-000000");
    }
}

#[cfg(test)]
mod registry_lifetime_tests {
    use super::*;

    /// Codex PR review finding 12 (P2): the FIFO cap (256) evicted the
    /// OLDEST registration even when its SecretString was still alive and
    /// in active use — a long-running daemon that refreshed tokens more
    /// than 256 times would log an early, still-active token verbatim.
    /// An alive secret must stay scrubbable regardless of how many other
    /// secrets were registered since.
    #[test]
    fn alive_secret_stays_scrubbable_past_any_registration_cap() {
        let first = SecretString::new("tok-alive-anchor-0001");
        const OLD_FIFO_CAP: usize = 256; // the pre-fix registry size
        for i in 0..(OLD_FIFO_CAP + 64) {
            // Churn secrets that die immediately.
            let _ = SecretString::new(format!("tok-churn-{i:04}"));
        }
        let leaked = format!("header Authorization={}", first.expose());
        assert_eq!(
            scrub(&leaked),
            "header Authorization=[redacted]",
            "a live secret must never age out of the registry"
        );
    }

    /// pr-champion WO-2: `SecretString::new` used to route its owned value
    /// through the borrowed `register(&value.into())`, whose `to_owned`
    /// stranded an unzeroized temporary copy of the secret on the heap. The
    /// owned path must take the caller's allocation by move. Red evidence
    /// pre-fix is the disclosed compile-red (`register_owned` did not
    /// exist); that the path makes no intermediate copy is inspection-level:
    /// `String` -> `Zeroizing::new` with no `clone`/`to_owned` in between.
    #[test]
    fn register_owned_moves_the_allocation_and_tracks_its_lifetime() {
        let value = String::from("tok-owned-move-0007");
        let handle = register_owned(value);
        // Alive: the moved allocation is registered and scrubbable.
        assert_eq!(
            scrub("Authorization: tok-owned-move-0007"),
            "Authorization: [redacted]"
        );
        // Dead: once the last handle drops, the value falls out of
        // scrubbing (the registry prunes it on the next pass).
        drop(handle);
        assert_eq!(
            scrub("Authorization: tok-owned-move-0007"),
            "Authorization: tok-owned-move-0007"
        );
    }

    /// The flip side: once the last handle is dropped, the value stops
    /// being scrubbed — the registry cannot grow without bound.
    #[test]
    fn dropped_secret_stops_being_scrubbed() {
        fn leak() {
            let secret = SecretString::new("tok-volatile-9876");
            assert_eq!(scrub(secret.expose()), REDACTED);
        }
        leak(); // the secret dies on return
        let _ = SecretString::new("tok-prune-trigger"); // prunes dead entries
        assert_eq!(
            scrub("x tok-volatile-9876 y"),
            "x tok-volatile-9876 y",
            "a dropped secret must fall out of the registry"
        );
    }
}
