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
    let terminal = match setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("protonwire-tui: cannot initialize terminal: {e}");
            std::process::exit(1);
        }
    };
    // From here on, every exit path restores the terminal first.
    let result = run(terminal, options);
    if let Err(e) = result {
        let _ = restore();
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
            "--socket" => socket = args.next().map(PathBuf::from),
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

type Backend = ratatui::crossterm::backend::CrosstermBackend<std::io::Stdout>;
type Term = Terminal<Backend>;

fn setup_terminal() -> std::io::Result<Term> {
    install_panic_hook();
    terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, terminal::EnterAlternateScreen)?;
    Terminal::with_options(
        ratatui::crossterm::backend::CrosstermBackend::new(stdout),
        TerminalOptions { viewport: Viewport::Fullscreen },
    )
}

fn restore() -> std::io::Result<()> {
    terminal::disable_raw_mode()?;
    execute!(std::io::stdout(), terminal::LeaveAlternateScreen)?;
    Ok(())
}

fn connect(options: &Options) -> Result<ProtonwireClient, ClientError> {
    let dev_unsafe =
        std::env::var(protonwire_client::DEV_UNSAFE_SOCKET_ENV).as_deref() == Ok("1");
    let checks = if dev_unsafe {
        protonwire_client::IpcSecurityChecks::dev_unchecked()
    } else {
        protonwire_client::IpcSecurityChecks::strict()
    };
    match options.socket.as_deref() {
        Some(path) => ProtonwireClient::connect_to(path, ClientSurface::Tui, checks),
        None if dev_unsafe => ProtonwireClient::connect_to(
            std::path::Path::new(protonwire_client::DEFAULT_SOCKET_PATH),
            ClientSurface::Tui,
            checks,
        ),
        None => ProtonwireClient::connect_default(ClientSurface::Tui),
    }
}

fn run(mut terminal: Term, options: Options) -> Result<(), ClientError> {
    let mut last_refresh = Instant::now() - REFRESH;
    let mut snapshot: Option<Result<DaemonState, String>> = None;
    let mut notice = String::new();
    loop {
        if last_refresh.elapsed() >= REFRESH {
            last_refresh = Instant::now();
            snapshot = Some(connect(&options).and_then(|mut c| c.state()).map_err(|e| e.to_string()));
        }
        terminal
            .draw(|frame| render(frame, snapshot.as_ref(), &notice))
            .map_err(ClientError::Io)?;
        while ratatui::crossterm::event::poll(POLL).map_err(ClientError::Io)? {
            if let TermEvent::Key(key) = ratatui::crossterm::event::read().map_err(ClientError::Io)? {
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

fn key_value<'a>(key: &str, value: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("{key:<20}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(value),
    ])
}
