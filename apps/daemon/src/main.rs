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
use std::sync::atomic::AtomicBool;

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
    let code = run(args, &init_tracing_filtered, Some(Path::new("/")));
    if code != 0 {
        std::process::exit(code);
    }
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
/// Configuration is loaded before tracing initializes so that
/// `daemon.log_level` from the config applies (rust-review finding 7);
/// a `--log-level` flag wins over the config, and RUST_LOG wins over
/// both. Load failures predate the logger and go to stderr.
fn run(args: Args, init_tracing: &dyn Fn(&str), trust_root: Option<&Path>) -> i32 {
    let mut paths = ConfigPaths::system();
    if let Some(config) = &args.config {
        paths.system_config = config.clone();
    }
    if let Some(socket_dir) = &args.socket_dir {
        paths.socket_dir = socket_dir.clone();
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
    let config_socket_path = config.daemon.socket_path.clone();
    let config_socket_group = config.daemon.socket_group.clone();
    let bus = Arc::new(protonwire_ipc::EventBus::new());
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
    });

    info!(
        socket = %server.socket_path().display(),
        version = env!("CARGO_PKG_VERSION"),
        "protonwire-daemon serving"
    );
    server.serve(handler, stop);
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

        let code = run(args, &init, None);
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
        let code = run(args, &init, Some(Path::new("/")));
        assert_eq!(
            code, 15,
            "a group-writable system configuration must fail the strict load with \
             the config exit code (PRD 9.8), never be applied silently"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
