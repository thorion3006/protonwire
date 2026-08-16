//! `protonwire-tui` — the Ratatui client skeleton (PRD 9.9, FR-127F).
//!
//! Milestone 1 renders the Dashboard view from live daemon state over the
//! shared client SDK and demonstrates the terminal-lifecycle guarantees:
//! alternate-screen setup, panic-hook restoration, and restore on normal
//! exit, error, and handled quit keys. The remaining eight views, focus
//! traversal, and confirmation dialogs land with Milestone 8 capability
//! completion; exiting the TUI never touches the tunnel (FR-127I).

use std::path::PathBuf;
use std::time::{Duration, Instant};

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

#[derive(Debug)]
struct Options {
    socket: Option<PathBuf>,
}

fn main() {
    let options = parse_args();
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

fn run(terminal: &mut Term, options: Options) -> Result<(), ClientError> {
    let mut last_refresh = Instant::now() - REFRESH;
    let mut snapshot: Option<Result<DaemonState, String>> = None;
    let mut notice = String::new();
    loop {
        if last_refresh.elapsed() >= REFRESH {
            last_refresh = Instant::now();
            snapshot = Some(
                connect(&options)
                    .and_then(|mut c| c.state())
                    .map_err(|e| e.to_string()),
            );
        }
        terminal
            .draw(|frame| render(frame, snapshot.as_ref(), &notice))
            .map_err(ClientError::Io)?;
        while ratatui::crossterm::event::poll(POLL).map_err(ClientError::Io)? {
            if let TermEvent::Key(key) =
                ratatui::crossterm::event::read().map_err(ClientError::Io)?
            {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                let quit = matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                    || (key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL));
                if quit {
                    return Ok(()); // exiting the client never disconnects (FR-127I)
                }
                notice = "view lands in milestone 8 (PRD 9.9)".into();
            }
        }
    }
}

fn render(
    frame: &mut ratatui::Frame,
    snapshot: Option<&Result<DaemonState, String>>,
    notice: &str,
) {
    let area = frame.area();
    let mut lines: Vec<Line> = Vec::new();
    match snapshot {
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
    if !notice.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("* {notice}"),
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

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
            || Err(io::Error::new(io::ErrorKind::Other, "raw mode")),
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
            || Err(io::Error::new(io::ErrorKind::Other, "raw mode")),
            || Err(io::Error::new(io::ErrorKind::Other, "alt screen")),
        );
        assert_eq!(outcome.unwrap_err().to_string(), "raw mode");
    }

    #[test]
    fn both_steps_succeeding_yields_ok() {
        attempt_both(|| Ok(()), || Ok(())).unwrap();
    }
}
