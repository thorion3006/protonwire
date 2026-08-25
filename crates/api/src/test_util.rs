//! Shared test support for the loopback wire seam (the M1
//! `protonwire-ipc::test_util` precedent applied to the api crate's M2
//! harnesses): the hand-written std HTTP/1.1 scripted responder and the
//! loopback `Environment` pieces three harnesses had grown verbatim
//! copies of (the S4 integration test, the S8 entitlements and S10
//! location wire tests — the S8 file's own header said "the S8 copy,
//! verbatim discipline").
//!
//! Compiled two ways, deliberately WITHOUT a feature and WITHOUT a
//! self dev-dependency (the M2 dev-cycle lesson: a test-only self-edge
//! builds the crate twice and the local and dependency instances
//! diverge, E0599 for the local view):
//!
//! * the crate's unit tests: `#[cfg(test)] mod test_util;` in lib.rs;
//! * the S4 integration test: `#[path = "../src/test_util.rs"] mod
//!   test_util;` in `crates/api/tests/wire.rs`.
//!
//! The module therefore references no `crate::` paths — it stands
//! alone on std, muon, and serde_json in both compilation contexts.
//!
//! The S6 catalog harness (`catalog.rs`) deliberately keeps its OWN
//! responder and runtime pieces: it speaks `Connection: close` per
//! exchange (a different wire discipline) over its own deterministic
//! `TestOs`/`TestRng` stack with `RetryPolicy::never()` for the
//! rate-limit fixtures; sharing here would couple that unit's
//! load-bearing differences to this module's keep-alive discipline.
//! The S8/S10 adapter BUILDERS also stay per-file for a type-opacity
//! reason: the adapters' `new<C>` seam is deliberately generic over
//! the muon session context, and a shared builder would have to name
//! muon's concrete `GenericContext<...>` internals.

use std::io::Read as _;
use std::io::Write as _;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use serde_json::Value;
use serde_json::json;

/// The anonymous-session mint muon performs before the first send on a
/// credential-less session (spike memo Q2) — the S6/S8 body the mint
/// step serves. (The S4 auth harness scripts its own richer mint whose
/// tokens its assertions pin.)
pub const ANON_SESSION_BODY: &str = r#"{"UID":"anon-uid","UserID":null,"AccessToken":"anon-token","RefreshToken":"anon-refresh","Scopes":["unauth"]}"#;

// ===========================================================================
// The std HTTP/1.1 keep-alive responder with scripted, computable
// responses
// ===========================================================================

/// One recorded request: method, path, headers (lower-cased names), and
/// body.
#[derive(Debug, Clone)]
pub struct Recorded {
    /// The request method (e.g. `POST`).
    pub method: String,
    /// The request path with any query string.
    pub path: String,
    /// The request headers, names lower-cased.
    pub headers: Vec<(String, String)>,
    /// The request body bytes (empty unless the client sent one).
    pub body: Vec<u8>,
}

impl Recorded {
    /// The first value of `name`, if the client sent it.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The recorded body parsed as JSON (for scripted-computed steps
    /// and assertions).
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("recorded body is JSON")
    }
}

/// One scripted response.
pub struct Response {
    /// The full status line tail (e.g. `"200 OK"`).
    pub status: &'static str,
    /// The response headers, written after `Content-Length`.
    pub headers: Vec<(String, String)>,
    /// The response body bytes.
    pub body: Vec<u8>,
}

impl Response {
    /// A JSON response: `Content-Type: application/json` plus the
    /// serialized `body`.
    pub fn json(status: &'static str, body: Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: serde_json::to_vec(&body).expect("serialize scripted body"),
        }
    }

    /// A JSON-typed response serving pre-built bytes verbatim (recorded
    /// fixtures and refusal envelopes): the body is NOT re-serialized,
    /// so fixture fidelity is byte-exact.
    pub fn bytes(status: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body,
        }
    }

    /// A muon-rest error envelope.
    pub fn error(status: &'static str, code: u16, message: &str) -> Self {
        Self::json(status, json!({"Code": code, "Error": message}))
    }

    /// A bodyless response (e.g. the empty `DELETE /auth/v4` ack).
    pub fn empty(status: &'static str) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

/// One exchange: serve `respond(&recorded)` for the request matching
/// `method`/`path` (the responder serves steps strictly in order and
/// asserts each request matches its step).
pub struct Step {
    /// The expected request method.
    pub method: &'static str,
    /// The expected request path (query strings are ignored when
    /// matching).
    pub path: String,
    /// Computes this step's response from the recorded request.
    pub respond: Box<dyn Fn(&Recorded) -> Response + Send>,
}

impl Step {
    /// A step serving the same static JSON `body` for every hit.
    pub fn static_json(
        method: &'static str,
        path: impl Into<String>,
        status: &'static str,
        body: Value,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            respond: Box::new(move |_| Response::json(status, body.clone())),
        }
    }

    /// A step serving pre-built JSON bytes verbatim (recorded
    /// fixtures): the body is not re-serialized.
    pub fn static_bytes(
        method: &'static str,
        path: impl Into<String>,
        status: &'static str,
        body: Vec<u8>,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            respond: Box::new(move |_| Response::bytes(status, body.clone())),
        }
    }

    /// The anonymous-session mint (`POST /auth/v4/sessions`) over
    /// [`ANON_SESSION_BODY`] — the harnesses whose assertions pin the
    /// `anon-token` bearer mint.
    pub fn anon_session() -> Self {
        Self::static_bytes(
            "POST",
            "/auth/v4/sessions",
            "200 OK",
            ANON_SESSION_BODY.as_bytes().to_vec(),
        )
    }

    /// A step whose response is computed from the recorded request (the
    /// real-SRP halves and mid-call observation closures).
    pub fn computed(
        method: &'static str,
        path: impl Into<String>,
        respond: impl Fn(&Recorded) -> Response + Send + 'static,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            respond: Box::new(respond),
        }
    }
}

/// Hard ceilings so an unexpected protocol stall fails the test instead
/// of hanging it (unified at the S8/S10 figure; the S4 harness's
/// original 30 s only lengthened how long a stall takes to fail).
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Serves the script sequentially over KEEP-ALIVE connections: the
/// client's whole exchange (anonymous-session mint, SRP handshake, 2FA,
/// ...) rides the one pooled HTTP/1.1 connection Muon's pool maintains —
/// exactly how the real API is spoken. A new connection is accepted
/// only when the client opens one (e.g. a resend after a scripted
/// error). Bounded waits so an unexpected stall fails the test instead
/// of hanging it; after the script the listener closes.
///
/// (Why not `Connection: close` per exchange, the way the S6 catalog
/// responder does it: closing under Muon's pooled sender triggers its
/// channel-closed retry path, whose redial stalls under the sync
/// adapter's foreign-thread `block_on` drive — observed as a 30 s
/// timeout with the retry connecting only at teardown. Keeping the
/// pooled connection alive avoids that path entirely and matches the
/// production wire.)
pub fn spawn_scripted(
    steps: Vec<Step>,
) -> (std::thread::JoinHandle<()>, u16, Arc<Mutex<Vec<Recorded>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&recorded);
    let handle = std::thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("responder nonblocking");
        let mut steps = steps.into_iter().peekable();
        'script: loop {
            if steps.peek().is_none() {
                break 'script;
            }
            // Wait for a connection (bounded poll; the client may still
            // be on the previous one, so this is not the only path).
            let waited = Instant::now();
            let mut stream = 'accept: loop {
                match listener.accept() {
                    Ok((stream, _)) => break 'accept stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if waited.elapsed() > ACCEPT_TIMEOUT {
                            break 'script;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("responder accept failed: {e}"),
                }
            };
            stream.set_nonblocking(false).expect("blocking stream");
            stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
            stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
            // Serve as many steps as the client pipelines onto this
            // connection; close when it closes or a read times out.
            while steps.peek().is_some() {
                let step = steps.next().expect("peeked");
                match read_request(&mut stream) {
                    Ok(recorded) => serve_exchange(&mut stream, step, recorded, &seen),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => panic!("responder read failed: {e}"),
                }
            }
        }
    });
    (handle, port, recorded)
}

/// Reads one request (headers + Content-Length body) from the live
/// connection.
fn read_request(stream: &mut TcpStream) -> std::io::Result<Recorded> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 8192];
    let header_end;
    loop {
        if let Some(pos) = find_terminator(&buf) {
            header_end = pos;
            break;
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed between requests",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_owned();
    let (method, path) = match request_line.split_once(' ') {
        Some((m, rest)) => (
            m.to_owned(),
            rest.split(' ').next().unwrap_or_default().to_owned(),
        ),
        None => (String::new(), String::new()),
    };
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let content_length = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Ok(Recorded {
        method,
        path,
        headers,
        body,
    })
}

/// Serves one scripted response on the live keep-alive connection.
fn serve_exchange(
    stream: &mut TcpStream,
    step: Step,
    recorded: Recorded,
    seen: &Mutex<Vec<Recorded>>,
) {
    // The responder enforces its own script: an unexpected exchange
    // fails the test here rather than deep inside muon's error
    // mapping. Query strings are ignored when matching paths.
    assert_eq!(
        recorded.method, step.method,
        "scripted step order: expected {} {}, got {} {}",
        step.method, step.path, recorded.method, recorded.path
    );
    let bare_path = recorded.path.split('?').next().unwrap_or(&recorded.path);
    assert_eq!(
        bare_path, step.path,
        "scripted step order: expected {} {}",
        step.method, step.path
    );
    let response = (step.respond)(&recorded);
    seen.lock().unwrap().push(recorded);
    let mut out = format!(
        "HTTP/1.1 {}\r\nContent-Length: {}\r\n",
        response.status,
        response.body.len()
    );
    for (k, v) in &response.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    stream
        .write_all(out.as_bytes())
        .expect("responder write head");
    stream
        .write_all(&response.body)
        .expect("responder write body");
    stream.flush().expect("responder flush");
}

fn find_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

// ===========================================================================
// The loopback environment and the shared client-builder pieces
// ===========================================================================

/// The custom environment: direct-class loopback `http://` servers
/// (spike memo Q3 — `Scheme::Http` skips TLS).
#[derive(Debug, Clone)]
pub struct LoopbackEnv {
    /// The direct servers, in preference order.
    pub servers: Vec<muon::common::Server>,
}

impl muon::env::Env for LoopbackEnv {
    fn servers(&self, _version: &muon::app::AppVersion) -> Vec<muon::common::Server> {
        self.servers.clone()
    }
    fn ar_pins(&self) -> Option<&muon::tls::pins::TlsPinSet> {
        None
    }
    fn api_pins(&self) -> Option<&muon::tls::pins::TlsPinSet> {
        None
    }
}

/// One direct loopback `http://` server on `port` — `Scheme::Http`
/// skips TLS entirely, and being the only direct server it is always
/// the one chosen (spike memo Q3).
pub fn loopback_env(port: u16) -> muon::Environment {
    let server: muon::common::Server = format!("http://127.0.0.1:{port}/")
        .parse()
        .expect("loopback server url");
    muon::Environment::new_custom(LoopbackEnv {
        servers: vec![server],
    })
}

/// TWO direct-class servers, the first dead — `find_available_sender`
/// must exhaust the dead direct server and proceed on the live one (the
/// direct/indirect partition path alternative routing rides; recorded
/// limit, spike memo Q3).
pub fn two_direct_servers_env(dead_port: u16, live_port: u16) -> muon::Environment {
    let servers: Vec<muon::common::Server> = [
        format!("http://127.0.0.1:{dead_port}/"),
        format!("http://127.0.0.1:{live_port}/"),
    ]
    .iter()
    .map(|url| url.parse().expect("loopback server url"))
    .collect();
    muon::Environment::new_custom(LoopbackEnv { servers })
}

/// A port nothing listens on (bind, learn the port, drop the listener).
pub fn dead_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// The ProtonWire SDK identity for the tests.
pub fn test_sdk() -> muon::common::sdk::Sdk {
    muon::common::sdk::Sdk::new("protonwire", env!("CARGO_PKG_VERSION"))
        .expect("valid sdk identity")
}
