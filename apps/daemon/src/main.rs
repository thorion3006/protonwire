//! `protonwire-daemon` — the privileged host (PRD 6.1).
//!
//! The daemon is deliberately thin: it loads and validates configuration,
//! constructs [`protonwire_core::DaemonCore`], serves the frontend API over
//! a Unix socket with peer-credential authorization, and owns process
//! lifecycle. All product behavior lives in core; the request handler and
//! event-sink bridge live in this crate's library so they are unit-testable,
//! and the startup body lives in [`run`] with the tracing factory
//! injectable so the config-load-to-logging hand-off is too.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Parser;
use protonwire_core::redact::init_tracing_filtered;
use protonwire_store::config::SystemConfig;
use protonwire_store::paths::ConfigPaths;
use tracing::{info, warn};

use protonwire_daemon::{BusSink, DaemonHandler};

#[derive(Debug, Parser)]
#[command(
    name = "protonwire-daemon",
    version,
    about = "ProtonWire daemon (privileged host)"
)]
struct Args {
    /// System configuration path (default: /etc/protonwire/config.yaml).
    #[arg(long)]
    config: Option<PathBuf>,
    /// IPC socket directory (default: /run/protonwire).
    #[arg(long)]
    socket_dir: Option<PathBuf>,
    /// Log level filter (overrides `daemon.log_level` from the config;
    /// RUST_LOG overrides both).
    #[arg(long)]
    log_level: Option<String>,
}

fn main() {
    let args = Args::parse();
    let code = run(args, &init_tracing_filtered, Some(Path::new("/")), None);
    if code != 0 {
        std::process::exit(code);
    }
}

/// Set by the SIGTERM/SIGINT/SIGHUP/SIGQUIT handler (M2 S12, the TUI's
/// R7-4 pattern); polled by the serve-loop watcher in [`run`].
static TERMINATE_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Terminating-signal landing pad (SIGTERM, SIGINT, SIGHUP, SIGQUIT).
///
/// ASYNC-SIGNAL-SAFETY CONSTRAINT (the TUI's R7-4 rule, verbatim in
/// spirit): this runs on an arbitrary thread, interrupted from arbitrary
/// code. The ENTIRE body is one store to a static atomic — no locks, no
/// allocation, no I/O, and above all no daemon teardown, any of which
/// could deadlock or corrupt state. The serve-loop watcher polls the
/// flag at a 50 ms cadence and performs the graceful drain on the main
/// thread: the daemon has no terminal to restore (the TUI's reason for
/// the pattern), so "restore on the main thread" is here "set the serve
/// stop flag and let `serve()`'s existing drain path finish" — sessions
/// flush their final responses, the drain ceiling still bounds
/// stragglers, and `run` returns 0.
extern "C" fn record_termination(_signal: nix::libc::c_int) {
    TERMINATE_REQUESTED.store(true, Ordering::Relaxed);
}

/// Installs the flag handler for SIGTERM, SIGINT, SIGHUP, and SIGQUIT
/// (the TUI's signal set: SIGTERM is the systemd stop signal, Ctrl-C and
/// Ctrl-\ bypass any CLI path, SIGHUP is the service manager's reload-
/// and-stop habit; the handler body is signal-agnostic, so one flag
/// store serves them all).
///
/// The workspace denies `unsafe_code`; this is the daemon's one audited
/// unsafe block (the Tauri shell and the TUI's R7-4 handler are the
/// other documented exceptions in kind), sound because the installed
/// handler writes only a static atomic — see [`record_termination`].
/// `SaFlags::empty()` — no SA_RESTART: the watcher must notice the
/// flag, not have syscalls paper over the signal.
#[allow(unsafe_code)]
fn install_terminate_handler() -> nix::Result<()> {
    use nix::sys::signal::{SaFlags, SigAction, SigHandler, Signal, sigaction};
    let action = SigAction::new(
        SigHandler::Handler(record_termination),
        SaFlags::empty(),
        nix::sys::signal::SigSet::empty(),
    );
    unsafe {
        sigaction(Signal::SIGTERM, &action)?;
        sigaction(Signal::SIGINT, &action)?;
        sigaction(Signal::SIGHUP, &action)?;
        sigaction(Signal::SIGQUIT, &action)?;
    }
    Ok(())
}

/// Bridges the signal flag to the serve loop's stop flag: polls
/// [`TERMINATE_REQUESTED`] at a 50 ms cadence until either a signal
/// lands (sets `stop`, so `serve()` drains and returns through the
/// existing graceful path) or the stop flag is set by something else
/// (an administrator's Shutdown request — the watcher then just
/// leaves).
fn watch_for_termination(stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            if TERMINATE_REQUESTED.load(Ordering::Relaxed) {
                info!(
                    "termination signal received; draining sessions through the \
                     serve stop path"
                );
                stop.store(true, Ordering::SeqCst);
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    })
}

/// The daemon body with the tracing factory injectable — the same seam
/// style as `IpcServer::bind_with_resolved` in crates/ipc (production
/// passes the real [`init_tracing_filtered`]; tests pass a capturing
/// factory). Exit codes: 15 for a config load/validation failure (PRD
/// 9.8), 1 for a bind failure, 0 after a clean shutdown.
///
/// `trust_root` is the round-8 X5 seam: production passes `Some("/")` —
/// the system document loads strict, sshd `StrictModes`-style, so the
/// file and every ancestor up to `/` must be root-owned, free of
/// group/world write bits, and symlink-free (anyone able to plant or
/// replace the document would control the root daemon; a violation exits
/// 15). `None` keeps the loader's plain semantics and exists for the
/// pre-existing `run` tests, whose temp-tree paths an unprivileged
/// runner cannot make root-owned (parameterized, not blanket-applied —
/// the per-UID overlay and ordinary test paths are unchanged).
///
/// `cache_dir` is the S9 (a) seam, same shape: production passes `None`
/// (the `ConfigPaths` cache location stands and the scheduler's strict
/// loads walk to `/`); tests pass a directory to plant the scheduler's
/// persisted documents under, which ALSO narrows the scheduler's walk
/// root to that directory — the hermetic-test opt-in (an unprivileged
/// runner cannot construct a root-owned tree anywhere, and the default
/// tree's existing ancestors — e.g. a world-writable /tmp — would
/// otherwise refuse every hermetic construction before the arm under
/// test). The seam moves WHERE the documents live and how deep the
/// walk goes; it never relaxes HOW existing components are judged, and
/// production (main) never takes it.
///
/// Configuration is loaded before tracing initializes so that
/// `daemon.log_level` from the config applies (rust-review finding 7);
/// a `--log-level` flag wins over the config, and RUST_LOG wins over
/// both. Load failures predate the logger and go to stderr.
fn run(
    args: Args,
    init_tracing: &dyn Fn(&str),
    trust_root: Option<&Path>,
    cache_dir: Option<&Path>,
) -> i32 {
    // M2 S12: the terminating-signal handler goes in FIRST — a signal
    // arriving during config load or bind is recorded in the flag, and
    // the serve-loop watcher (spawned before serve) converts it into
    // the stop flag the moment the loop exists, so a stop request can
    // never be lost to a startup window. Failure only costs the
    // signal-driven stop (the default disposition returns), so it is
    // reported, not fatal.
    if let Err(e) = install_terminate_handler() {
        eprintln!("protonwire-daemon: cannot install SIGTERM/SIGINT/SIGHUP/SIGQUIT handlers: {e}");
    }
    let mut paths = ConfigPaths::system();
    if let Some(config) = &args.config {
        paths.system_config = config.clone();
    }
    if let Some(socket_dir) = &args.socket_dir {
        paths.socket_dir = socket_dir.clone();
    }
    if let Some(cache_dir) = cache_dir {
        paths.cache_dir = cache_dir.to_path_buf();
    }

    // Round-8 X5 [ZkI1F]: the system document is root-daemon policy, so
    // it loads strict — sshd `StrictModes`-style: the file and every
    // ancestor up to the trust root must be root-owned, free of
    // group/world write bits, and a real file/directory (no symlinks).
    // Anyone able to plant or replace the document would otherwise
    // control the root daemon. A violation is a hard load error and takes
    // the exit-15 path below; the `--config` flag overrides WHERE the
    // document lives, never the trust rule applied to it.
    let loaded = match trust_root {
        Some(trust_root) => SystemConfig::load_strict(&paths.system_config, trust_root),
        None => SystemConfig::load(&paths.system_config),
    };
    let loaded = match loaded {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("protonwire-daemon: {e}");
            return 15; // PRD 9.8: config validation failed
        }
    };
    let level = args
        .log_level
        .clone()
        .unwrap_or_else(|| loaded.config.daemon.log_level.clone());
    init_tracing(&level);
    // pr-champion WO-9: SystemConfig::load warns about a missing file
    // before any subscriber exists, so that record is discarded — re-emit
    // it now that tracing is initialized, or operators would never learn
    // the daemon is running on built-in defaults. FU-A pins this hand-off
    // through the injected factory (see the tests below).
    if loaded.used_defaults {
        warn!(
            path = %paths.system_config.display(),
            "system configuration not found; using defaults"
        );
    }
    let config = Arc::new(loaded.config);

    // Codex PR review finding 4: capture daemon.socket_path before `config`
    // moves into the core; binding applies it with --socket-dir > config >
    // default precedence (see resolve_bind_location). daemon.socket_group
    // rides along (pr-champion WO-7): the socket is chowned to that group
    // so unprivileged clients can reach a root-owned socket (PRD 6.3).
    // R9-1: the config default is now Some("protonwire") — the packaged
    // group — and bind_with_group applies the hand-off only when running
    // as root, so dev launches without the group are unaffected.
    let config_socket_path = config.daemon.socket_path.clone();
    let config_socket_group = config.daemon.socket_group.clone();
    let bus = Arc::new(protonwire_ipc::EventBus::new());
    // The S9 service construction below needs the validated policy too;
    // both holders share one Arc.
    let config_for_services = Arc::clone(&config);
    let core = Arc::new(protonwire_core::DaemonCore::new(
        env!("CARGO_PKG_VERSION"),
        config,
        Arc::new(BusSink(Arc::clone(&bus))),
    ));
    let (socket_dir, socket_name) = protonwire_daemon::resolve_bind_location(
        args.socket_dir.as_deref(),
        config_socket_path.as_deref(),
        &paths.socket_dir,
        &paths.socket_name,
    );
    // M2 S9 (a): the scheduler constructs STRICTLY, and any refusal —
    // a malformed, oversized, or fs-trust-refused persisted deadlines
    // or cache document — ABORTS startup (exit 15, the PRD 9.8
    // config-class code). Never a default-fallback scheduler: silently
    // re-deriving deadlines from defaults would forget the persisted
    // high-water mark and re-arm the FR-13H restart refetch storm the
    // strict load exists to prevent. Production walks to `/`; the
    // `cache_dir` seam (tests) additionally narrows the walk root to
    // the injected directory — the hermetic-test opt-in, since an
    // unprivileged runner cannot construct a root-owned tree anywhere.
    let services = match &cache_dir {
        None => protonwire_daemon::DaemonServices::build(Arc::clone(&config_for_services), &paths),
        Some(dir) => protonwire_daemon::DaemonServices::build_with_trust_root(
            Arc::clone(&config_for_services),
            &paths,
            dir,
        ),
    };
    let services = match services {
        Ok(services) => Arc::new(services),
        Err(e) => {
            eprintln!("protonwire-daemon: {e}");
            return 15;
        }
    };
    let server = match protonwire_ipc::server::IpcServer::bind_with_group(
        &socket_dir,
        &socket_name,
        config_socket_group.as_deref(),
    ) {
        Ok(server) => server,
        Err(e) => {
            eprintln!(
                "protonwire-daemon: cannot bind {}: {e}",
                socket_dir.join(&socket_name).display()
            );
            return 1;
        }
    };
    core.notice(
        protonwire_frontend_api::NoticeLevel::Info,
        "daemon started (milestone 1 foundation)",
    );

    let stop = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(DaemonHandler {
        core: Arc::clone(&core),
        stop: Arc::clone(&stop),
        bus,
        services,
    });

    info!(
        socket = %server.socket_path().display(),
        version = env!("CARGO_PKG_VERSION"),
        "protonwire-daemon serving"
    );
    // M2 S12: the signal flag's bridge into the serve loop. Joined after
    // serve returns — the watcher leaves on the stop flag whichever way
    // it was set (signal or administrator Shutdown), so the join is
    // prompt and never outlives the drain it may itself have started.
    let terminate_watcher = watch_for_termination(Arc::clone(&stop));
    // Codex PR#4 P1 (M2 S9 completion): the scheduler's AUTOMATIC door
    // needs a driver — constructing the scheduler services no window.
    // FR-12/FR-13C: this loop fetches the first-boot due window and
    // every persisted deadline that becomes due, independent of any
    // user issuing ServersRefresh. Until the session lane installs the
    // catalog adapter, its windows fail with the empty cell's typed
    // transport refusal (logged once per window); the loop itself is
    // the missing production wiring. Joined after serve returns so a
    // stop never races a live refresh.
    let refresh_driver = protonwire_daemon::spawn_automatic_refresh_driver(
        Arc::clone(&handler.services.scheduler),
        Arc::clone(&stop),
    );
    server.serve(handler, stop);
    let _ = terminate_watcher.join();
    let _ = refresh_driver.join();
    info!("protonwire-daemon stopped");
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// In-order log capture: the marker the injected factory pushes plus
    /// every tracing event recorded after it installs its subscriber.
    ///
    /// The daemon crate keeps `tracing-subscriber` out of its direct
    /// dependencies (core owns subscriber construction), so the capture is
    /// the plain `tracing` trait surface: a `Subscriber` that collects just
    /// each event's `message` field.
    #[derive(Default, Clone)]
    struct EventLog {
        entries: Arc<Mutex<Vec<String>>>,
    }

    impl EventLog {
        fn push(&self, entry: String) {
            self.entries.lock().unwrap().push(entry);
        }

        fn snapshot(&self) -> Vec<String> {
            self.entries.lock().unwrap().clone()
        }
    }

    /// Collects an event's `message` field; all other fields are ignored.
    struct MessageVisitor(String);

    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }

    impl tracing::Subscriber for EventLog {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = MessageVisitor(String::new());
            event.record(&mut visitor);
            self.push(visitor.0);
        }

        // `run` emits events only; the span surface is trait boilerplate.
        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            tracing::span::Id::from_u64(NEXT.fetch_add(1, Ordering::Relaxed))
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// FU-A (rust-reviewer round 6, Medium): deleting the `used_defaults`
    /// re-emit kept the whole suite green — the store flag was tested, but
    /// the user-visible warning lived in `main` with no test (and no
    /// dead-code warning, since the field is read from another crate).
    /// This pins the re-emit through the `run` seam: a missing config file
    /// must produce the "using defaults" warning AFTER the injected tracing
    /// factory ran, because load's own `warn!` fires before any subscriber
    /// exists and is discarded (pr-champion WO-9).
    #[test]
    fn defaults_warning_is_re_emitted_after_tracing_init() {
        // Hermetic scratch dir: a missing config path under it selects the
        // defaults path, and a regular file squatting on the socket-dir
        // path makes `create_dir_all` (inside bind) fail — so `run`
        // terminates with the bind-failure exit code instead of reaching
        // the serve loop.
        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-fua-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"").unwrap();
        // Hermetic scheduler cache (S9 a): all-absent, so the strict
        // construction is the clean first boot on every runner.
        let cache_dir = dir.join("var/cache/protonwire");

        let args = Args {
            config: Some(dir.join("missing-config.yaml")),
            socket_dir: Some(blocker),
            log_level: None,
        };

        let log = EventLog::default();
        let init = {
            let log = log.clone();
            move |level: &str| {
                log.push(format!("tracing initialized (level={level})"));
                // One capturing install per process: this is the only test
                // here that calls `run`.
                tracing::subscriber::set_global_default(log.clone())
                    .expect("capturing subscriber installs once per process");
            }
        };

        let code = run(args, &init, None, Some(&cache_dir));
        assert_eq!(code, 1, "the blocked socket directory must fail the bind");

        let entries = log.snapshot();
        // The factory ran first, with the config's default level (no
        // --log-level was given): load happens before init by design.
        assert_eq!(
            entries.first().map(String::as_str),
            Some("tracing initialized (level=info)"),
            "tracing must initialize before the re-emit: {entries:?}"
        );
        // And the defaults warning is re-emitted after it, or operators
        // would never learn the daemon runs on built-in defaults.
        let warning = entries
            .iter()
            .position(|entry| entry.contains("system configuration not found; using defaults"))
            .expect("the defaults warning must be re-emitted after tracing init");
        assert!(
            warning > 0,
            "the warning must follow the init marker: {entries:?}"
        );
    }

    /// M2 S12: the signal path end to end — delivery, flag, bridge, and
    /// clean stop — with ONE signal. kill(getpid(), ...) from a spawned
    /// thread must land in the handler (whose entire effect is a flag
    /// store — async-signal-safe, benign for every other test in this
    /// process), the flag must be observable by polling, and the serve
    /// loop's watcher must convert it into the stop flag so `run`
    /// returns the clean-shutdown code 0 after the graceful drain. A
    /// handshaken client is connected before the signal so the drain
    /// path is exercised for real (its session must be torn down by the
    /// stop, not by us).
    ///
    /// Red (behavioral, observed at stage A — handler and flag present,
    /// the serve loop not yet watching): SIGTERM landed, the flag was
    /// observed set, and `run` kept serving until the watchdog fired —
    /// nothing bridged the flag to the stop flag. (Without the handler
    /// at all the signal would have killed the whole test process; the
    /// flag handler ships first, the bridge second.)
    ///
    /// No separate delivery test: two tests signalling the process in
    /// parallel reset each other's shared flag mid-observation (the
    /// TUI's R7-4 suite runs its signals one at a time for exactly this
    /// reason) — the first draft's standalone delivery test raced THIS
    /// test's handshake with its own SIGTERM.
    #[test]
    fn delivered_sigterm_sets_the_flag_and_stops_the_serving_daemon_cleanly() {
        use protonwire_frontend_api::{ClientMessage, ClientSurface, ServerMessage};
        use std::os::unix::net::UnixStream;

        install_terminate_handler().expect("handler installs");
        TERMINATE_REQUESTED.store(false, Ordering::Relaxed);

        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-sigterm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Hermetic scheduler cache (S9 a): all-absent, so the strict
        // construction is the clean first boot on every runner.
        let cache_dir = dir.join("var/cache/protonwire");
        let args = Args {
            config: Some(dir.join("missing-config.yaml")),
            socket_dir: Some(dir.clone()),
            log_level: None,
        };

        let (exit_tx, exit_rx) = std::sync::mpsc::channel::<i32>();
        std::thread::spawn(move || {
            // No subscriber install (the FU-A test owns the process's
            // single global install); trust_root None keeps the loader
            // on its plain semantics for the scratch-tree path.
            let _ = exit_tx.send(run(args, &|_level: &str| {}, None, Some(&cache_dir)));
        });

        // Wait for the socket, then handshake a live session through it.
        let socket = dir.join("protonwire.sock");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !socket.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the daemon never bound its socket"
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let mut stream = UnixStream::connect(&socket).expect("client connects");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        protonwire_ipc::frame::write_msg(
            &mut stream,
            &ClientMessage::Hello {
                protocol_version: 1,
                client: protonwire_frontend_api::ClientInfo {
                    name: "sigterm-test".into(),
                    version: "0".into(),
                    surface: ClientSurface::Other,
                },
            },
        )
        .unwrap();
        match protonwire_ipc::frame::read_msg::<_, ServerMessage>(&mut stream).unwrap() {
            ServerMessage::HelloAck(_) => {} // a live, handshaken session
            other => panic!("expected the hello ack, got {other:?}"),
        }

        // SIGTERM to self from a helper — ONLY after the handshake: the
        // accept loop polls at 250 ms, so a signal sent earlier can beat
        // the accept entirely and the drain has nothing to drain (the
        // un-accepted connect is reset with the listener instead).
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGTERM)
                .unwrap();
        });
        // The flag half of the contract: the delivered signal was
        // recorded, observable by polling (bounded by the same watchdog
        // that expects run() to return).
        let started = std::time::Instant::now();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !TERMINATE_REQUESTED.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            TERMINATE_REQUESTED.load(Ordering::Relaxed),
            "delivered SIGTERM was not observed"
        );
        // And the stop half: the watcher bridged the flag to the serve
        // loop, which drained and returned the clean-shutdown code.
        let code = exit_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("run() must return after SIGTERM — pre-fix it served forever");
        assert_eq!(code, 0, "a signalled stop is a clean shutdown");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the signal-driven stop took {:?} — the drain must stay inside its ceiling",
            started.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S9 (a): the scheduler constructs through the STRICT production
    /// path, and a corrupted persisted-deadlines document REFUSES
    /// STARTUP — exit 15, before the bind — never a default-fallback
    /// scheduler. Silently re-deriving deadlines from defaults would
    /// re-arm exactly the FR-13H refetch storm the persisted high-water
    /// mark exists to prevent (a rollback-forgetting daemon hammering
    /// Proton on every restart). Pre-fix red: `run` had no scheduler
    /// construction at all — this test drove straight past the planted
    /// deadlines document and died at the blocked socket directory with
    /// exit 1, not 15.
    ///
    /// Arm disclosure (the honest red-evidence nuance): on an
    /// unprivileged runner the walk's ownership pass refuses the
    /// test-planted (necessarily non-root-owned) document before the
    /// parse arm is reached — the refusal class is FsTrust; a
    /// root-owned tree reaches the Malformed arm (each store-arm class
    /// is pinned by the deadlines/catalog suites). Both are the
    /// prescribed abort classes (Malformed/TooLarge/FsTrust), and both
    /// exit 15 here — the pinned contract is the REFUSAL.
    #[test]
    fn corrupted_deadlines_document_refuses_startup_before_bind() {
        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-s9a-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache_dir = dir.join("var/cache/protonwire");
        std::fs::create_dir_all(&cache_dir).unwrap();
        // Corrupted persisted deadlines: unparseable bytes.
        std::fs::write(cache_dir.join("deadlines.json"), b"{not json").unwrap();
        // The bind blocker makes the PRE-fix outcome deterministic: with
        // no scheduler construction, `run` reaches the bind and exits 1.
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"").unwrap();

        let args = Args {
            config: Some(dir.join("missing-config.yaml")),
            socket_dir: Some(blocker),
            log_level: None,
        };
        let code = run(args, &|_level: &str| {}, None, Some(&cache_dir));
        assert_eq!(
            code, 15,
            "a corrupted deadlines document must refuse startup with the \
             config-class exit code, never serve (and never fall back to \
             default deadlines)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S9 (a), no-fallback control arm: an all-ABSENT cache tree is the
    /// legitimate first boot (the FR-13F bootstrap) and must not abort
    /// anything — the daemon proceeds to the bind (exit 1 here, only
    /// because of the blocker). This kills the inverse mutation ("abort
    /// whenever the scheduler looks at the cache directory"). The cache
    /// directory is deliberately NOT created: absent components are
    /// soft (MissingLeaf::Allow), so the walk passes on every runner.
    #[test]
    fn absent_deadlines_document_is_a_normal_first_boot() {
        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-s9a-ctrl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // The cache tree itself is deliberately NOT created: absent
        // components are soft, so the strict construction passes.
        let cache_dir = dir.join("var/cache/protonwire");
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"").unwrap();

        let args = Args {
            config: Some(dir.join("missing-config.yaml")),
            socket_dir: Some(blocker),
            log_level: None,
        };
        let code = run(args, &|_level: &str| {}, None, Some(&cache_dir));
        assert_eq!(
            code, 1,
            "first boot with no persisted deadlines must reach the bind \
             (exit 1 is the blocker, not a scheduler refusal)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S9 (d), FR-7J at the startup boundary: a config naming the
    /// systemd credential source with no systemd credentials directory
    /// behind it ($CREDENTIALS_DIRECTORY absent — asserted as the
    /// test's precondition) is a misdeployment that REFUSES STARTUP
    /// (exit 15), never a silently-blank source. Toggle-red (the
    /// credential resolution removed from the service construction):
    /// `run` sailed past resolution to the blocked socket dir, exit 1.
    #[test]
    fn systemd_credential_source_without_systemd_refuses_startup() {
        assert!(
            std::env::var_os("CREDENTIALS_DIRECTORY").is_none(),
            "this test's premise is a systemd-free environment"
        );
        let dir =
            std::env::temp_dir().join(format!("protonwire-daemon-s9d-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.yaml");
        std::fs::write(
            &config,
            "schema_version: 2\naccount:\n  credential_input_source: systemd\n",
        )
        .unwrap();
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"").unwrap();

        let args = Args {
            config: Some(config),
            socket_dir: Some(blocker),
            log_level: None,
        };
        let code = run(args, &|_level: &str| {}, None, Some(&dir.join("cache")));
        assert_eq!(
            code, 15,
            "a systemd source with no credentials directory must refuse startup \
             (FR-7J), never serve with a silently-blank source"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Round-8 X5 [ZkI1F]: the daemon applies the system configuration as
    /// root, so the document's path is a privilege-escalation surface —
    /// pre-fix, a group-writable config.yaml was read and applied without
    /// a murmur (the red for this test: `run` sailed past config load and
    /// died at the blocked socket directory with exit 1, not 15). The
    /// strict load must reject the file before anything is applied from
    /// it: exit 15, the existing config-failure path (PRD 9.8). This is
    /// the production call: trust root `/`, the walk-to-`/` rule.
    #[test]
    fn strict_mode_rejects_group_writable_config_before_serving() {
        use std::os::unix::fs::PermissionsExt;
        // Hermetic scratch dir (FU-A pattern): the group-writable config
        // under it is the finding's scenario; a regular file squatting on
        // the socket-dir path guarantees the PRE-fix run terminates at the
        // bind (exit 1) instead of ever serving, so the red is
        // deterministic. The defect fires on the file component itself —
        // the deepest in the walk — so the rejection holds whether the
        // runner is root or not (the world-writable /tmp above the scratch
        // dir is never reached).
        let dir = std::env::temp_dir().join(format!("protonwire-daemon-x5-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config_dir = dir.join("etc/protonwire");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config = config_dir.join("config.yaml");
        std::fs::write(&config, "schema_version: 2\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o664)).unwrap();
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"").unwrap();

        let args = Args {
            config: Some(config),
            socket_dir: Some(blocker),
            log_level: None,
        };
        // No subscriber install here: the FU-A test owns the process's
        // single global install; this test pins only the exit code (the
        // defect naming is pinned by the store suite).
        let init = |_level: &str| {};
        let code = run(args, &init, Some(Path::new("/")), None);
        assert_eq!(
            code, 15,
            "a group-writable system configuration must fail the strict load with \
             the config exit code (PRD 9.8), never be applied silently"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
