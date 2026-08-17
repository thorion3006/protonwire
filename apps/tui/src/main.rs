//! `protonwire-tui` — the Ratatui client skeleton (PRD 9.9, FR-127F).
//!
//! Milestone 1 renders the Dashboard view from live daemon state over the
//! shared client SDK and demonstrates the terminal-lifecycle guarantees:
//! alternate-screen setup, panic-hook restoration, and restore on normal
//! exit, error, and handled quit keys. Daemon state refreshes on a
//! background thread (pr-champion R7-3) so a stalled daemon can no longer
//! freeze input and redraw: connect+GetState run off the render/poll
//! thread and snapshots cross a bounded newest-wins channel. SIGTERM,
//! SIGHUP, SIGINT, and SIGQUIT restore the terminal too (pr-champion
//! R7-4; round 7 added SIGINT/SIGQUIT): the handler only
//! sets an async-signal-safe flag that the main loop polls and turns into
//! restore+exit on the main thread. The remaining eight views, focus
//! traversal, and confirmation dialogs land with Milestone 8 capability
//! completion; exiting the TUI never touches the tunnel (FR-127I).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nix::sys::signal::{SaFlags, SigAction, SigHandler, Signal, sigaction};
use ratatui::crossterm::event::{Event as TermEvent, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::crossterm::{execute, terminal};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{Terminal, TerminalOptions, Viewport};

use protonwire_client::{ClientError, ProtonwireClient};
use protonwire_frontend_api::{ClientSurface, DaemonState};

/// Refresh cadence for daemon state.
const REFRESH: Duration = Duration::from_millis(750);

/// Key-poll interval while waiting between refreshes.
const POLL: Duration = Duration::from_millis(50);

/// Two missed refreshes before a snapshot is called stale (R7-3): one
/// dropped tick can be scheduling noise, two means the daemon (or the
/// refresh thread's connect+GetState) is not keeping up and the frame
/// must say so instead of presenting old state as live.
const STALE_AFTER: Duration = Duration::from_millis(1500);

/// How long [`RefreshWorker::shutdown`] waits for the refresh thread
/// before detaching it.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);

/// Stop-flag polling slice for the refresh thread's sleep between
/// fetches, so `shutdown` is observed promptly instead of after a full
/// [`REFRESH`] period.
const STOP_SLICE: Duration = Duration::from_millis(25);

/// A daemon snapshot as the refresh thread delivers it: the state, or the
/// error string the render path already knows how to present as the
/// unreachable-daemon state.
type Snapshot = Result<DaemonState, String>;

/// A snapshot paired with the instant its fetch COMPLETED in the refresh
/// worker (round 7): staleness measures from fetch time, so a snapshot
/// that sat in the bounded channel — or was drained late by a slow render
/// loop — still renders with its true age instead of passing as fresh.
type StampedSnapshot = (Instant, Snapshot);

#[derive(Debug)]
struct Options {
    socket: Option<PathBuf>,
}

fn main() {
    let options = parse_args();
    // R7-4: catch SIGTERM/SIGHUP/SIGINT/SIGQUIT before the terminal is
    // touched. Failure only costs the signal-driven restore (the default
    // disposition returns), so it is reported, not fatal.
    if let Err(e) = install_terminate_handler() {
        eprintln!("protonwire-tui: cannot install SIGTERM/SIGHUP/SIGINT/SIGQUIT handlers: {e}");
    }
    let mut terminal = match setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("protonwire-tui: cannot initialize terminal: {e}");
            std::process::exit(1);
        }
    };
    // From here on, EVERY exit path restores the terminal: ratatui's own
    // Drop only restores the cursor, not raw mode or the alternate screen,
    // so normal quit must restore explicitly (rust-review finding 3,
    // FR-127F).
    let result = run(&mut terminal, options);
    let _ = restore();
    if let Err(e) = result {
        eprintln!("protonwire-tui: {e}");
        std::process::exit(1);
    }
}

/// Installs a panic hook that restores the terminal before the default
/// hook prints, so a panic never leaves the console in raw mode
/// (PRD FR-127F).
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore();
        default_hook(info);
    }));
}

fn parse_args() -> Options {
    let mut socket = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => match args.next() {
                Some(value) => socket = Some(PathBuf::from(value)),
                None => {
                    eprintln!("protonwire-tui: --socket requires a value");
                    std::process::exit(2);
                }
            },
            "--version" => {
                println!("protonwire-tui {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => {
                eprintln!("protonwire-tui: unknown argument {other}");
                std::process::exit(2);
            }
        }
    }
    Options { socket }
}

type Backend = ratatui::backend::CrosstermBackend<std::io::Stdout>;
type Term = Terminal<Backend>;

fn setup_terminal() -> std::io::Result<Term> {
    install_panic_hook();
    // Each mutation is rolled back if a LATER step fails (Codex PR review
    // finding 8): `?` on EnterAlternateScreen or Terminal construction
    // returned to main with raw mode still on (or stuck on the alternate
    // screen) and no Term existing, so main's restore() never ran and the
    // user's shell was left broken. Explicit matches, not `?`, so every
    // completed step is undone on the way out.
    terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    if let Err(e) = execute!(stdout, terminal::EnterAlternateScreen) {
        let _ = terminal::disable_raw_mode();
        return Err(e);
    }
    match Terminal::with_options(
        ratatui::backend::CrosstermBackend::new(stdout),
        TerminalOptions {
            viewport: Viewport::Fullscreen,
        },
    ) {
        Ok(term) => Ok(term),
        Err(e) => {
            let _ = restore();
            Err(e)
        }
    }
}

fn restore() -> std::io::Result<()> {
    attempt_both(terminal::disable_raw_mode, || {
        execute!(std::io::stdout(), terminal::LeaveAlternateScreen)
    })
}

/// Attempts two independent teardown steps, running BOTH even when the
/// first fails (pr-champion WO-8): `?` on disable_raw_mode used to return
/// before LeaveAlternateScreen ran, potentially leaving the user on the
/// alternate screen. The first error is reported.
fn attempt_both(
    first: impl FnOnce() -> std::io::Result<()>,
    second: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    match (first(), second()) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
    }
}

fn connect(options: &Options) -> Result<ProtonwireClient, ClientError> {
    // Trust-check policy (including the debug-only bypass) lives in the
    // SDK (refactorer step 3).
    protonwire_client::connect_with_socket_override(options.socket.as_deref(), ClientSurface::Tui)
}

/// Set by the SIGTERM/SIGHUP/SIGINT/SIGQUIT handler (R7-4); polled by the
/// main loop.
static TERMINATE_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Terminating-signal landing pad (SIGTERM, SIGHUP, SIGINT, SIGQUIT).
///
/// ASYNC-SIGNAL-SAFETY CONSTRAINT (R7-4): this runs on an arbitrary
/// thread, interrupted from arbitrary code. The ENTIRE body is one store
/// to a static atomic — no locks, no allocation, no I/O, and above all no
/// terminal restoration, any of which could deadlock or corrupt state.
/// The main loop polls the flag at its existing <=POLL (50ms) event-poll
/// cadence and performs restore+exit on the main thread. Relaxed ordering
/// suffices: the flag publishes no other data.
extern "C" fn record_termination(_signal: nix::libc::c_int) {
    TERMINATE_REQUESTED.store(true, Ordering::Relaxed);
}

/// Installs the flag handler for SIGTERM, SIGHUP, SIGINT, and SIGQUIT
/// (R7-4; round 7 added SIGINT/SIGQUIT — Ctrl-C and Ctrl-\ bypass the
/// quit-key path, and the handler body is signal-agnostic, so the same
/// flag store serves them). Signals bypass unwind, so the panic hook
/// never runs and raw mode plus the alternate screen used to leak on
/// `kill`; with the handler in place the loop observes the flag and
/// tears down through the same restore path as a quit key.
///
/// The workspace denies `unsafe_code`; this is the TUI's one audited
/// unsafe block, sound because the installed handler writes only a
/// static atomic (see [`record_termination`]). `SaFlags::empty()` —
/// no SA_RESTART because it would not restart poll(2) anyway, and the
/// loop must notice the flag, not have syscalls paper over the signal.
/// EINTR note (sec round 7): crossterm 0.29 retries `Interrupted` event
/// reads internally (mio.rs:80), so a signal landing mid-poll surfaces
/// as a fresh poll window rather than a propagated error — the flag is
/// observed within one POLL (50 ms) cadence either way.
#[allow(unsafe_code)]
fn install_terminate_handler() -> nix::Result<()> {
    let action = SigAction::new(
        SigHandler::Handler(record_termination),
        SaFlags::empty(),
        nix::sys::signal::SigSet::empty(),
    );
    unsafe {
        sigaction(Signal::SIGTERM, &action)?;
        sigaction(Signal::SIGHUP, &action)?;
        sigaction(Signal::SIGINT, &action)?;
        sigaction(Signal::SIGQUIT, &action)?;
    }
    Ok(())
}

/// Whether the loop should keep running after a termination check.
enum Flow {
    Continue,
    Exit,
}

/// The signal-observed path, extracted so it is unit-testable (R7-4):
/// when the handler's flag is set, restore FIRST — on the main thread,
/// never inside the handler — and report [`Flow::Exit`] so the loop
/// unwinds promptly (a lingering worker shutdown cannot delay the
/// restore). `main`'s own restore still runs afterwards and is
/// idempotent.
fn termination_check(flag: &AtomicBool, restore: impl FnOnce() -> std::io::Result<()>) -> Flow {
    if flag.load(Ordering::Relaxed) {
        let _ = restore();
        Flow::Exit
    } else {
        Flow::Continue
    }
}

/// One refresh cycle: connect + GetState, mapped exactly as the inline
/// refresh used to map it. Runs on the refresh thread (R7-3).
fn fetch_snapshot(options: &Options) -> Snapshot {
    connect(options)
        .and_then(|mut client| client.state())
        .map_err(|e| e.to_string())
}

/// Background refresh worker (pr-champion R7-3): connect+GetState run on
/// their own thread on the [`REFRESH`] tick, and snapshots cross to the
/// render/poll thread through a depth-1 bounded channel with `try_send`.
/// Newest-wins with a bounded channel means the worker NEVER blocks on a
/// slow consumer, and a dropped snapshot is stale by construction (a
/// newer fetch is already scheduled) — the frame's staleness marker is
/// what tells the user. A stalled daemon stalls only this thread; the
/// render/poll thread keeps drawing the last snapshot, marking it stale,
/// and polling keys.
struct RefreshWorker {
    stop: Arc<AtomicBool>,
    done: Receiver<()>,
    handle: Option<JoinHandle<()>>,
}

impl RefreshWorker {
    /// Production wiring: the SDK connect+GetState fetch on the
    /// [`REFRESH`] tick.
    fn start_refresh(options: Options) -> (Self, Receiver<StampedSnapshot>) {
        Self::start(move || fetch_snapshot(&options), REFRESH)
    }

    /// Core spawn with an injectable fetch, so the stall test can point
    /// the worker at an accepting-but-never-responding stub daemon.
    fn start<F>(mut fetch: F, period: Duration) -> (Self, Receiver<StampedSnapshot>)
    where
        F: FnMut() -> Snapshot + Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let handle = std::thread::Builder::new()
            .name("protonwire-refresh".into())
            .spawn(move || {
                while !flag.load(Ordering::SeqCst) {
                    // Depth-1 newest-wins: a full channel means the render
                    // loop still holds a newer snapshot, so dropping this
                    // one is correct (and never blocks this thread).
                    // Round 7: the timestamp is captured HERE, at fetch
                    // completion — never at drain time — so the render
                    // loop cannot launder an old snapshot as fresh.
                    let snapshot = fetch();
                    let fetched_at = Instant::now();
                    let _ = tx.try_send((fetched_at, snapshot));
                    let next_tick = Instant::now() + period;
                    while !flag.load(Ordering::SeqCst) {
                        let remaining = next_tick.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            break;
                        }
                        std::thread::sleep(remaining.min(STOP_SLICE));
                    }
                }
                let _ = done_tx.send(());
            })
            .expect("spawn the refresh thread");
        (
            Self {
                stop,
                done: done_rx,
                handle: Some(handle),
            },
            rx,
        )
    }

    /// Signals stop and waits briefly for the thread to acknowledge. The
    /// flag is honored between fetches and inside the inter-fetch sleep,
    /// but a fetch ALREADY blocked on a stalled daemon cannot be
    /// interrupted; after [`SHUTDOWN_GRACE`] the thread is detached — it
    /// exits when its transport deadline lapses — so the quit path never
    /// waits on the very stall this worker exists to absorb.
    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        match self.done.recv_timeout(SHUTDOWN_GRACE) {
            Ok(()) => {
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
            }
            Err(_) => self.handle = None, // detach the stalled thread
        }
    }
}

impl Drop for RefreshWorker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The key events the loop actually consults, decoupled from crossterm's
/// full `KeyEvent` so the loop-state machine is testable without a tty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyInput {
    code: KeyCode,
    ctrl: bool,
}

/// The render decision for one frame (the loop's output side): the newest
/// snapshot, whether it has gone stale, and the notice line.
struct DashboardView<'a> {
    snapshot: Option<&'a Snapshot>,
    stale: bool,
    notice: &'a str,
}

/// Loop-state machine (pr-champion R7-3): `run()`'s per-frame state —
/// the newest snapshot, its age, and the notice — with the quit decision
/// for key presses and the staleness rule for rendering. Extracted so the
/// frame behavior is pinnable against a stalling daemon without a
/// terminal.
struct LoopState {
    snapshot: Option<Snapshot>,
    snapshot_at: Option<Instant>,
    started_at: Instant,
    notice: String,
}

impl LoopState {
    fn new() -> Self {
        Self {
            snapshot: None,
            snapshot_at: None,
            started_at: Instant::now(),
            notice: String::new(),
        }
    }

    /// Records a snapshot drained from the refresh worker, stamped at
    /// `at` — the worker's fetch-completion instant (injected so
    /// staleness is deterministically testable; round 7: the stamp is
    /// taken at FETCH time in the worker, so a snapshot drained late by a
    /// slow render loop still renders with its true age).
    fn on_snapshot(&mut self, snapshot: Snapshot, at: Instant) {
        self.snapshot = Some(snapshot);
        self.snapshot_at = Some(at);
    }

    /// Applies one key press; `true` means quit. Non-quit keys update the
    /// notice exactly as the inline handler did.
    fn on_key(&mut self, key: KeyInput) -> bool {
        let quit = matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
            || (key.code == KeyCode::Char('c') && key.ctrl);
        if !quit {
            self.notice = "view lands in milestone 8 (PRD 9.9)".into();
        }
        quit
    }

    /// The frame's render decision at `now`: the last snapshot and
    /// whether it is stale — older than [`STALE_AFTER`] since the last
    /// snapshot (or since start, when none ever arrived).
    fn view(&self, now: Instant) -> DashboardView<'_> {
        let age_reference = self.snapshot_at.unwrap_or(self.started_at);
        DashboardView {
            snapshot: self.snapshot.as_ref(),
            stale: now.saturating_duration_since(age_reference) >= STALE_AFTER,
            notice: &self.notice,
        }
    }
}

impl Default for LoopState {
    fn default() -> Self {
        Self::new()
    }
}

fn run(terminal: &mut Term, options: Options) -> Result<(), ClientError> {
    // R7-3: connect+GetState live on the refresh thread; the render/poll
    // thread only drains snapshots (never blocking) and renders.
    let (mut worker, snapshots) = RefreshWorker::start_refresh(options);
    let mut drain = move || snapshots.try_recv().ok();
    let mut state = LoopState::new();
    let mut draw = |view: &DashboardView<'_>| -> std::io::Result<()> {
        terminal.draw(|frame| render(frame, view)).map(|_| ())
    };
    let mut poll = || -> std::io::Result<Option<KeyInput>> {
        if ratatui::crossterm::event::poll(POLL)?
            && let TermEvent::Key(key) = ratatui::crossterm::event::read()?
            && key.kind == KeyEventKind::Press
        {
            return Ok(Some(KeyInput {
                code: key.code,
                ctrl: key.modifiers.contains(KeyModifiers::CONTROL),
            }));
        }
        Ok(None)
    };
    let result = drive(
        &mut drain,
        &mut state,
        &TERMINATE_REQUESTED,
        &restore,
        &mut draw,
        &mut poll,
    );
    worker.shutdown();
    result.map_err(ClientError::Io)
}

/// The loop proper (pr-champion R7-3): `run()`'s frame cycle with every
/// tty concern injected — where snapshots come from (a drain that must
/// never block), how one key-poll window yields an event, and where the
/// render decision goes. `run()` wires crossterm and the Terminal; the
/// tests wire a stalling daemon and synthetic keys, which is what makes
/// "keys and redraws keep flowing during a stall" pinnable at all.
/// Processes at most one key per frame; at the frame cadence (one POLL
/// window plus a draw) that is indistinguishable from draining the whole
/// backlog per redraw. Each frame also polls the SIGTERM/SIGHUP/SIGINT/
/// SIGQUIT flag (R7-4) and takes the restore+exit path on the main
/// thread.
fn drive(
    drain: &mut dyn FnMut() -> Option<StampedSnapshot>,
    state: &mut LoopState,
    terminate: &AtomicBool,
    restore: &dyn Fn() -> std::io::Result<()>,
    draw: &mut dyn FnMut(&DashboardView<'_>) -> std::io::Result<()>,
    poll: &mut dyn FnMut() -> std::io::Result<Option<KeyInput>>,
) -> std::io::Result<()> {
    loop {
        // Round 7: the worker's fetch-completion instant travels WITH the
        // snapshot — stamping here (at drain time) would present a
        // dropped-then-drained-late snapshot as fresh.
        while let Some((fetched_at, snapshot)) = drain() {
            state.on_snapshot(snapshot, fetched_at);
        }
        if let Flow::Exit = termination_check(terminate, restore) {
            return Ok(());
        }
        draw(&state.view(Instant::now()))?;
        if let Some(key) = poll()?
            && state.on_key(key)
        {
            return Ok(()); // exiting the client never disconnects (FR-127I)
        }
    }
}

fn render(frame: &mut ratatui::Frame, view: &DashboardView<'_>) {
    let area = frame.area();
    let mut lines: Vec<Line> = Vec::new();
    match view.snapshot {
        None => lines.push(Line::from("connecting to daemon…")),
        Some(Ok(state)) => {
            lines.push(key_value("State", &state.vpn_state.to_string()));
            lines.push(key_value("Integration", state.network_integration.as_str()));
            lines.push(key_value("Daemon", &state.daemon_version));
            if let Some(owner) = state.active_owner_uid {
                lines.push(key_value("Owner UID", &owner.to_string()));
            }
        }
        Some(Err(e)) => lines.push(Line::from(Span::styled(
            format!("daemon unavailable: {e}"),
            Style::default().fg(Color::Red),
        ))),
    }
    if view.stale {
        lines.push(Line::from(Span::styled(
            "(stale — still waiting on the daemon)",
            Style::default().fg(Color::Yellow),
        )));
    }
    if !view.notice.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("* {notice}", notice = view.notice),
            Style::default().add_modifier(Modifier::DIM),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "q quit · other views land in milestone 8",
        Style::default().add_modifier(Modifier::DIM),
    )));
    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" ProtonWire — Dashboard "),
    );
    frame.render_widget(paragraph, area);
}

fn key_value(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{key:<20}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(value.to_owned()),
    ])
}

#[cfg(test)]
mod tests {
    use super::attempt_both;
    use std::io;
    use std::io::Read;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::TrySendError;
    use std::time::{Duration, Instant};

    use protonwire_frontend_api::{NetworkIntegration, PROTOCOL_VERSION, VpnState};
    use ratatui::crossterm::event::KeyCode;

    use super::{
        DashboardView, Flow, KeyInput, LoopState, RefreshWorker, STALE_AFTER, Snapshot,
        StampedSnapshot, TERMINATE_REQUESTED, drive, install_terminate_handler, termination_check,
    };

    fn test_state() -> super::DaemonState {
        super::DaemonState {
            protocol_version: PROTOCOL_VERSION,
            daemon_version: "test-daemon".into(),
            vpn_state: VpnState::Disconnected,
            network_integration: NetworkIntegration::Auto,
            active_owner_uid: None,
            latest_event_seq: None,
        }
    }

    /// pr-champion WO-8: restore() used `?` on disable_raw_mode, so a raw
    /// mode teardown failure returned before LeaveAlternateScreen ran and
    /// could leave the user stranded on the alternate screen. The teardown
    /// steps must be attempted independently; the first error is reported.
    /// No tty exists in CI, so this pins the structure (both closures are
    /// attempted) rather than the real crossterm calls; restore() wiring
    /// those calls through attempt_both is inspection-level.
    #[test]
    fn second_step_is_attempted_when_the_first_fails() {
        let second_ran = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&second_ran);
        let outcome = attempt_both(
            || Err(io::Error::other("raw mode")),
            move || {
                marker.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(outcome.is_err());
        assert!(
            second_ran.load(Ordering::SeqCst),
            "LeaveAlternateScreen must still be attempted when disable_raw_mode fails"
        );
    }

    #[test]
    fn first_error_wins_when_both_steps_fail() {
        let outcome = attempt_both(
            || Err(io::Error::other("raw mode")),
            || Err(io::Error::other("alt screen")),
        );
        assert_eq!(outcome.unwrap_err().to_string(), "raw mode");
    }

    #[test]
    fn both_steps_succeeding_yields_ok() {
        attempt_both(|| Ok(()), || Ok(())).unwrap();
    }

    /// pr-champion R7-3: a daemon that accepts the connection and then
    /// never answers used to freeze the whole UI — connect+GetState ran
    /// on the only thread polling input and redrawing, so the handshake
    /// and request deadlines (10s each by default) blocked every frame.
    /// This pins the fix: while the refresh fetch is stalled on a real
    /// accepting-but-silent Unix socket, the loop keeps redrawing and
    /// observes the quit key promptly. The full `run()` loop is
    /// tty-coupled, so the tested unit is the extracted loop (`drive`)
    /// fed by the production snapshot source (the worker's bounded
    /// channel) with the key stream injected. Red evidence: the same test
    /// with the drain running the fetch inline on the loop thread (the
    /// old synchronous design) misses the quit deadline because frame
    /// processing blocks inside the fetch.
    #[test]
    fn keys_and_redraws_keep_flowing_while_the_daemon_stalls() {
        let dir = std::env::temp_dir().join(format!("protonwire-tui-r73-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join("stalled.sock");
        let _ = std::fs::remove_file(&socket_path);
        // The accepting-but-stalling stub daemon: accepts every
        // connection and holds it open, never reading or writing.
        let listener = UnixListener::bind(&socket_path).unwrap();
        let _acceptor = std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
            }
        });

        // The fetch behaves like the SDK against this stub: connect, then
        // wait on a reply that never comes until a (shortened) deadline.
        let stall = Duration::from_millis(900);
        let fetch_path = socket_path.clone();
        let (mut worker, snapshots) = RefreshWorker::start(
            move || {
                let mut stream = UnixStream::connect(&fetch_path).unwrap();
                stream.set_read_timeout(Some(stall)).unwrap();
                let mut byte = [0u8; 1];
                let _ = stream.read(&mut byte); // blocks out the stall
                Err("stalled daemon (test stub)".to_string())
            },
            super::REFRESH,
        );

        let quit_at = Instant::now() + Duration::from_millis(150);
        // Watchdog: if the loop is ever starved this hard, fail the test
        // instead of hanging it.
        let starved_at = Instant::now() + Duration::from_millis(2000);
        let draws = Arc::new(AtomicUsize::new(0));
        let draw_counter = Arc::clone(&draws);
        let mut drain = move || snapshots.try_recv().ok();
        let mut draw = move |_view: &DashboardView<'_>| -> io::Result<()> {
            draw_counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let mut poll = move || -> io::Result<Option<KeyInput>> {
            std::thread::sleep(Duration::from_millis(20)); // one poll window
            if Instant::now() >= starved_at {
                return Err(io::Error::other("loop starved: keys are not being polled"));
            }
            Ok((Instant::now() >= quit_at).then_some(KeyInput {
                code: KeyCode::Char('q'),
                ctrl: false,
            }))
        };
        let mut state = LoopState::new();
        let started = Instant::now();
        let no_signal = AtomicBool::new(false);
        let outcome = drive(
            &mut drain,
            &mut state,
            &no_signal,
            &|| Ok(()),
            &mut draw,
            &mut poll,
        );
        let elapsed = started.elapsed();
        worker.shutdown();
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir(&dir);

        outcome.unwrap();
        assert!(
            elapsed < Duration::from_millis(450),
            "quit took {elapsed:?} — the loop blocked on the stalled daemon"
        );
        assert!(
            draws.load(Ordering::SeqCst) >= 3,
            "redraws stopped during the stall"
        );
    }

    /// pr-champion R7-3: the staleness marker — a snapshot survives one
    /// missed refresh but two ([`STALE_AFTER`]) mark the frame stale so
    /// old state is never presented as live.
    #[test]
    fn snapshots_older_than_two_refreshes_are_marked_stale() {
        let mut state = LoopState::new();
        let t0 = Instant::now();
        state.on_snapshot(Ok(test_state()), t0);
        let fresh = state.view(t0 + super::REFRESH);
        assert!(!fresh.stale);
        assert!(fresh.snapshot.is_some_and(Snapshot::is_ok));
        assert!(state.view(t0 + STALE_AFTER).stale);
    }

    /// pr-champion R7-3: a daemon whose very first connect stalls shows
    /// "connecting" and then goes stale too, not "connecting" forever.
    #[test]
    fn a_snapshot_that_never_arrives_also_goes_stale() {
        let state = LoopState::new();
        let t0 = Instant::now();
        let early = state.view(t0);
        assert!(early.snapshot.is_none());
        assert!(!early.stale);
        assert!(state.view(t0 + STALE_AFTER).stale);
    }

    /// pr-champion R7-3: unreachable-daemon snapshots (the refresh
    /// thread's error strings, unchanged from the inline refresh) surface
    /// through the view for the existing red "daemon unavailable" render.
    #[test]
    fn unreachable_daemon_snapshots_carry_the_error() {
        let mut state = LoopState::new();
        state.on_snapshot(Err("connection refused (test)".into()), Instant::now());
        let view = state.view(Instant::now());
        assert!(
            view.snapshot
                .is_some_and(|s| matches!(s, Err(e) if e.contains("connection refused")))
        );
        assert!(!view.stale);
    }

    /// pr-champion R7-3: the quit decision, unchanged from the inline
    /// handler — q, Esc, Ctrl-C quit; any other key only sets the notice.
    #[test]
    fn quit_keys_are_q_escape_and_ctrl_c() {
        let mut state = LoopState::new();
        assert!(state.on_key(KeyInput {
            code: KeyCode::Char('q'),
            ctrl: false
        }));
        assert!(state.on_key(KeyInput {
            code: KeyCode::Esc,
            ctrl: false
        }));
        assert!(state.on_key(KeyInput {
            code: KeyCode::Char('c'),
            ctrl: true
        }));
        assert!(!state.on_key(KeyInput {
            code: KeyCode::Char('x'),
            ctrl: false
        }));
        assert!(!state.on_key(KeyInput {
            code: KeyCode::Char('c'),
            ctrl: false
        }));
        assert_eq!(state.notice, "view lands in milestone 8 (PRD 9.9)");
    }

    /// pr-champion R7-3: the bounded channel's load-bearing property — a
    /// full channel makes the worker DROP the snapshot, never block on
    /// the render loop.
    #[test]
    fn a_full_snapshot_channel_drops_instead_of_blocking() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<StampedSnapshot>(1);
        let t0 = Instant::now();
        tx.try_send((t0, Err("first".into()))).unwrap();
        let started = Instant::now();
        let dropped = tx.try_send((t0, Err("second".into())));
        assert!(started.elapsed() < Duration::from_millis(50));
        assert!(matches!(dropped, Err(TrySendError::Full(_))));
        assert!(
            matches!(rx.try_recv(), Ok((at, Err(e))) if e == "first" && at == t0),
            "the surviving snapshot must keep its own fetch stamp"
        );
    }

    /// Round 7 (F5): staleness must measure from FETCH time, not drain
    /// time. The worker stamps a snapshot when its fetch completes, so a
    /// snapshot drained late by a slow render loop — the exact shape of a
    /// dropped-then-rescheduled refresh — must render with the stale
    /// marker, not pass as fresh. Red by mutation: reverting drive() to
    /// stamp Instant::now() at drain makes this fail (the marker misses).
    #[test]
    fn a_snapshot_drained_late_is_stale_by_its_fetch_time() {
        let stale_fetch_at = Instant::now() - STALE_AFTER - Duration::from_millis(50);
        let stale_seen = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&stale_seen);
        let mut drained = false;
        let mut drain = move || {
            if drained {
                None
            } else {
                drained = true;
                Some((stale_fetch_at, Ok(test_state())))
            }
        };
        let mut draw = move |view: &DashboardView<'_>| -> io::Result<()> {
            if view.snapshot.is_some() {
                marker.store(view.stale, Ordering::SeqCst);
            }
            Ok(())
        };
        let mut poll = || -> io::Result<Option<KeyInput>> {
            Ok(Some(KeyInput {
                code: KeyCode::Char('q'),
                ctrl: false,
            }))
        };
        let mut state = LoopState::new();
        let no_signal = AtomicBool::new(false);
        drive(
            &mut drain,
            &mut state,
            &no_signal,
            &|| Ok(()),
            &mut draw,
            &mut poll,
        )
        .unwrap();
        assert!(
            stale_seen.load(Ordering::SeqCst),
            "a snapshot fetched more than STALE_AFTER ago must render with \
             the stale marker even though it was just drained"
        );
    }

    /// pr-champion R7-3: shutdown must not wait out a stalled fetch — the
    /// worker detaches after the grace period and quit stays responsive.
    #[test]
    fn shutdown_detaches_a_stalled_fetch_instead_of_waiting() {
        let dir = std::env::temp_dir().join(format!(
            "protonwire-tui-r73-shutdown-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join("stalled.sock");
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();
        let _acceptor = std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
            }
        });
        let fetch_path = socket_path.clone();
        let (mut worker, _snapshots) = RefreshWorker::start(
            move || {
                let mut stream = UnixStream::connect(&fetch_path).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(30)))
                    .unwrap();
                let mut byte = [0u8; 1];
                let _ = stream.read(&mut byte);
                Err("stalled daemon (test stub)".to_string())
            },
            super::REFRESH,
        );
        let started = Instant::now();
        worker.shutdown();
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir(&dir);
        assert!(
            started.elapsed() < Duration::from_millis(1000),
            "shutdown waited out a stalled fetch"
        );
    }

    /// pr-champion R7-4: the signal-observed path — a set flag runs the
    /// restore exactly once and takes the exit path; a clear flag leaves
    /// the terminal alone and continues.
    #[test]
    fn a_set_termination_flag_restores_and_exits() {
        let flag = AtomicBool::new(false);
        assert!(matches!(
            termination_check(&flag, || Ok(())),
            Flow::Continue
        ));
        flag.store(true, Ordering::Relaxed);
        let restored = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&restored);
        assert!(matches!(
            termination_check(&flag, move || {
                marker.store(true, Ordering::SeqCst);
                Ok(())
            }),
            Flow::Exit
        ));
        assert!(restored.load(Ordering::SeqCst));
    }

    /// pr-champion R7-4: real signal delivery. kill(getpid(), ...) from a
    /// spawned thread must land in the handler (which only sets the
    /// static flag — async-signal-safe, so this is benign for every other
    /// test in the process) and be observable by polling, then take the
    /// restore+exit path. Round 7 extended the loop to SIGINT and SIGQUIT
    /// — both new registrations delivered for real, one signal at a time
    /// (a second concurrent signal test could reset the shared flag
    /// mid-observation and fail spuriously). Full signal-delivery tests
    /// are fragile in CI; this one is deterministic because the handler's
    /// entire effect is a flag store and the sender thread cannot race
    /// the install (install runs first, on the test thread).
    #[test]
    fn delivered_terminate_signals_set_the_flag_and_exit_through_restore() {
        install_terminate_handler().unwrap();
        for signal in [
            nix::sys::signal::Signal::SIGTERM,
            nix::sys::signal::Signal::SIGINT,
            nix::sys::signal::Signal::SIGQUIT,
        ] {
            TERMINATE_REQUESTED.store(false, Ordering::Relaxed);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(25));
                nix::sys::signal::kill(nix::unistd::Pid::this(), signal).unwrap();
            });
            let deadline = Instant::now() + Duration::from_secs(5);
            while !TERMINATE_REQUESTED.load(Ordering::Relaxed) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(
                TERMINATE_REQUESTED.load(Ordering::Relaxed),
                "delivered {signal:?} was not observed"
            );
        }
        let restored = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&restored);
        assert!(matches!(
            termination_check(&TERMINATE_REQUESTED, move || {
                marker.store(true, Ordering::SeqCst);
                Ok(())
            }),
            Flow::Exit
        ));
        assert!(restored.load(Ordering::SeqCst));
        TERMINATE_REQUESTED.store(false, Ordering::Relaxed);
    }
}
