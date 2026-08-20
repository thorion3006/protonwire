//! Server-catalog retrieval through the Muon transport (FR-8, M2 S6).
//!
//! Muon models no `/vpn` endpoints (spike memo Q7), so the catalog is a
//! ProtonWire-owned typed request sent through `Session::send_with_sdk` —
//! PRD 6.5's sanctioned path for endpoints Muon does not model: the
//! single required transport, its alternative routing included
//! (FR-13A), and no second Proton HTTP stack.
//!
//! Conditional refresh (FR-13E) lives entirely at this layer (spike
//! memo Q4): Muon has no first-class ETag machinery, so the adapter
//! attaches `If-None-Match` via `HttpReq::header` and classifies the
//! response itself — `HttpRes::ok()` accepts 3xx, so a 304 flows back
//! here where `is(NOT_MODIFIED)` selects [`CatalogFetch::NotModified`].
//!
//! The trait is synchronous (the daemon's trust boundary, M1 posture);
//! the adapter bridges to Muon's async engine through an injected
//! [`BlockOn`] closure rather than a hard runtime dependency — S4 wires
//! the engine runtime at the daemon; tests inject a dedicated tokio
//! runtime.
//!
//! The wire seam (hermetic proof the spike deferred): the tests below
//! drive the REAL hyper transport — SRP-free anonymous session minting,
//! header injection, the 401-refresh machinery's headers — against a
//! hand-written std HTTP/1.1 responder on a loopback `TcpListener`,
//! pointed at by a custom `Environment::new_custom` env (spike memo Q3:
//! `Scheme::Http` skips TLS, so no certificates are involved).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use muon::common::ServiceType;
use muon::common::sdk::Sdk;
use muon::http::{HttpReq, Method};

use crate::{ApiError, CatalogApi, CatalogFetch};

/// The server-catalog endpoint. ProtonWire-owned typed request per
/// spike memo Q7.
pub const CATALOG_PATH: &str = "/vpn/logicals";

/// End-to-end time budget for one catalog fetch (the document is a few
/// MiB; 30 s is deliberately generous while still bounded).
pub const CATALOG_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound applied to a parsed `Retry-After` delay at this seam
/// (S9 sec-tracked clamp): 30 days.
///
/// The availability-vs-PRD trade, recorded: the PRD mandates HONORING
/// Proton's `Retry-After` (ER-16 — a signalled rate limit outranks even
/// a confirmed manual refresh), so the clamp never touches an honest
/// delay; it bounds only the hostile shape. An unclamped
/// `Retry-After: 1000000000` (~31,700 years) would permanently
/// suppress the single-flight scheduler — persisted, immune to restart
/// and confirmation — converting one hostile response into a permanent
/// denial of the server catalog, which the availability side of the
/// PRD cannot accept either. Thirty days is far past every honest
/// Proton delay observed (seconds to days) and short enough that the
/// floor survives an operator's attention span; the three-hour
/// greatest-of floor still applies beneath it either way.
pub const RETRY_AFTER_CEILING_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Parses one `Retry-After` header value (S9, tracked since S6).
///
/// Only the SECONDS form (`digits`) is honored. The HTTP-date form is
/// REFUSED — disclosed: pinned Muon surfaces no date parser, and
/// deriving "now + delta" from a local wall clock that may be wrong
/// (the S7 rollback guard exists because it can be) would fabricate a
/// suppression deadline the upstream never sent. A refusal yields
/// `None`, which STILL classifies the response as rate-limited: the
/// scheduler mints the greatest-of floor (Q4 — a delay-less rate limit
/// is still a rate limit), so refusing the date form is fail-closed,
/// not a bypass. Every parsed value is clamped at
/// [`RETRY_AFTER_CEILING_SECONDS`] (see its doc for the trade).
fn parse_retry_after(value: Option<&str>) -> Option<u64> {
    // Parsed as u128 so a delay beyond u64's range CLAMPS (it is
    // certainly past the ceiling) instead of degrading to the floor —
    // only non-numeric shapes (the refused date form, garbage) refuse.
    let seconds = value?.trim().parse::<u128>().ok()?;
    Some(
        u64::try_from(seconds)
            .unwrap_or(u64::MAX)
            .min(RETRY_AFTER_CEILING_SECONDS),
    )
}

/// One in-flight catalog request, as presented to the blocking bridge.
pub type FetchFuture = Pin<Box<dyn Future<Output = muon::Result<muon::ProtonResponse>>>>;

/// The sync→async bridge: blocks on a Muon response future. Injected at
/// construction (the repo's seam-injection idiom) so this crate depends
/// on no runtime; the daemon's engine runtime arrives with S4.
pub type BlockOn = Arc<dyn Fn(FetchFuture) -> muon::Result<muon::ProtonResponse> + Send + Sync>;

type SendCatalog = Arc<dyn Fn(HttpReq) -> muon::Result<muon::ProtonResponse> + Send + Sync>;

/// [`CatalogApi`] over a Muon session.
///
/// The session is captured at construction into a sending closure (it
/// must be `Send + Sync` there, provable where the context type is
/// concrete), so the adapter itself is a plain `Send + Sync` type that
/// drops the context generic — the `&dyn CatalogApi` seam S7/S9 inject.
pub struct MuonCatalog {
    send: SendCatalog,
}

impl MuonCatalog {
    /// Wraps `session`. `sdk` identifies ProtonWire in
    /// `x-pm-origin-sdk` (register the same [`Sdk`] on the client
    /// builder); `block_on` bridges to the engine runtime.
    pub fn new<C: muon::Context>(session: muon::Session<C>, sdk: Sdk, block_on: BlockOn) -> Self
    where
        muon::Session<C>: Send + Sync + 'static,
    {
        let session = Arc::new(session);
        let sdk = Arc::new(sdk);
        let send = Arc::new(move |req: HttpReq| {
            let session = Arc::clone(&session);
            let sdk = Arc::clone(&sdk);
            block_on(Box::pin(
                async move { session.send_with_sdk(req, &sdk).await },
            ))
        });
        Self { send }
    }

    /// The conditional GET. `ServiceType::Background` per Muon's own
    /// taxonomy ("examples: cache refresh"); idempotent, so Muon may
    /// race transports for it.
    fn catalog_request(etag: Option<&str>) -> HttpReq {
        let mut req = HttpReq::new(Method::GET, CATALOG_PATH)
            .allowed_time(CATALOG_FETCH_TIMEOUT)
            .service_type(ServiceType::Background, true);
        if let Some(etag) = etag {
            req = req.header(("If-None-Match", etag));
        }
        req
    }
}

impl CatalogApi for MuonCatalog {
    fn fetch(&self, etag: Option<&str>) -> Result<CatalogFetch, ApiError> {
        let res = (self.send)(Self::catalog_request(etag))
            .map_err(|e| ApiError::Transport(format!("catalog transport failure: {e}")))?;
        // The pacing classification runs BEFORE `ok()` (which consumes
        // the response): a 429/503 is a transport-level SUCCESS whose
        // headers carry the scheduler's suppression input (S9, the
        // obligation tracked since S6). Both statuses map to
        // [`ApiError::RateLimited`] — a 503 with no usable
        // `Retry-After` still rate-limits (Q4: `None` suppresses to
        // the floor).
        let status = res.status();
        if status == muon::http::Status::TOO_MANY_REQUESTS
            || status == muon::http::Status::SERVICE_UNAVAILABLE
        {
            let retry_after = res
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| parse_retry_after(Some(value)));
            return Err(ApiError::RateLimited {
                retry_after_seconds: retry_after,
            });
        }
        // ok() accepts 3xx, so the 304 reaches this layer (spike Q4).
        let res = res.ok().map_err(|err| {
            ApiError::Transport(format!(
                "catalog endpoint refused: HTTP {} ({err})",
                err.0.as_u16()
            ))
        })?;
        if res.is(muon::http::Status::NOT_MODIFIED) {
            return Ok(CatalogFetch::NotModified);
        }
        let etag = res
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        Ok(CatalogFetch::Changed {
            etag,
            body: res.into_body(),
        })
    }
}

// ---------------------------------------------------------------------------
// Wire seam — hermetic tests through the real Muon hyper transport
// (spike memo Q3, decision 2). Everything below is test-only.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod wire_tests {
    use std::io::{Read as _, Write as _};
    use std::net::{IpAddr, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::*;

    /// The recorded catalog fixture — the same contract document the
    /// store-side model tests parse (`protonwire-store/src/catalog_fixture.json`),
    /// so the transport and the model provably speak about the same wire.
    const FIXTURE: &str = include_str!("../../store/src/catalog_fixture.json");

    /// What the anonymous-session mint returns (muon-rest
    /// `SessionCredentials`, PascalCase; spike memo Q2). Scopes are
    /// arbitrary: no scope check gates a plain send.
    const ANON_SESSION_BODY: &str = r#"{"UID":"anon-uid","UserID":null,"AccessToken":"anon-token","RefreshToken":"anon-refresh","Scopes":["unauth"]}"#;

    // ===== the hand-written std HTTP/1.1 responder ==========================

    /// One recorded request: method, path, and the headers seen
    /// (lower-cased names).
    #[derive(Debug, Clone)]
    struct Recorded {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
    }

    impl Recorded {
        fn header(&self, name: &str) -> Option<&str> {
            let name = name.to_ascii_lowercase();
            self.headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.as_str())
        }
    }

    /// One scripted response, with the request the responder expects to
    /// be serving it.
    struct Step {
        method: &'static str,
        path: &'static str,
        status: &'static str,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    }

    impl Step {
        /// The anonymous-session mint muon performs before the first
        /// send on a credential-less session (spike memo: unauth
        /// sessions).
        fn anon_session() -> Self {
            Self {
                method: "POST",
                path: "/auth/v4/sessions",
                status: "200 OK",
                headers: vec![("Content-Type", "application/json".into())],
                body: ANON_SESSION_BODY.as_bytes().to_vec(),
            }
        }

        /// The catalog response.
        fn catalog(status: &'static str, etag: Option<&str>, body: Vec<u8>) -> Self {
            let extra = etag
                .map(|etag| vec![("ETag", etag.to_owned())])
                .unwrap_or_default();
            Self::catalog_with_headers(status, extra, body)
        }

        /// The catalog response with arbitrary extra headers (the
        /// rate-limit fixtures' `Retry-After`).
        fn catalog_with_headers(
            status: &'static str,
            extra: Vec<(&'static str, String)>,
            body: Vec<u8>,
        ) -> Self {
            let mut headers = vec![("Content-Type", "application/json".into())];
            headers.extend(extra);
            Self {
                method: "GET",
                path: CATALOG_PATH,
                status,
                headers,
                body,
            }
        }
    }

    /// Serves the script sequentially, one connection per step
    /// (`Connection: close`), recording every request. Bounded waits so
    /// an unexpected protocol stall fails the test instead of hanging
    /// it; after the script the listener closes.
    fn spawn_responder(
        script: Vec<Step>,
    ) -> (std::thread::JoinHandle<()>, u16, Arc<Mutex<Vec<Recorded>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&recorded);
        let handle = std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("responder nonblocking");
            'script: for step in script {
                let waited = Instant::now();
                let stream = 'accept: loop {
                    match listener.accept() {
                        Ok((stream, _)) => break 'accept stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Poll accept with a hard ceiling.
                            if waited.elapsed() > ACCEPT_TIMEOUT {
                                break 'script;
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("responder accept failed: {e}"),
                    }
                };
                serve_exchange(stream, step, &seen);
            }
        });
        (handle, port, recorded)
    }

    /// Hard ceiling for waiting for the next expected connection.
    const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
    const READ_TIMEOUT: Duration = Duration::from_secs(10);

    /// Reads one request (headers + any Content-Length body), records
    /// it, serves the scripted response, closes.
    fn serve_exchange(mut stream: TcpStream, step: Step, seen: &Mutex<Vec<Recorded>>) {
        stream.set_nonblocking(false).expect("blocking stream");
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(READ_TIMEOUT)).unwrap();

        // Read to the header terminator.
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(pos) = find_terminator(&buf) {
                buf.truncate(pos);
                break;
            }
            let n = stream.read(&mut chunk).expect("responder read");
            if n == 0 {
                panic!("responder: EOF before header terminator");
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let text = String::from_utf8_lossy(&buf).into_owned();
        let mut lines = text.split("\r\n");
        let request_line = lines.next().unwrap_or_default().to_owned();
        let mut method = String::new();
        let mut path = String::new();
        if let Some((m, rest)) = request_line.split_once(' ') {
            method = m.to_owned();
            path = rest.split(' ').next().unwrap_or_default().to_owned();
        }
        let headers: Vec<(String, String)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        // Drain any body the client claims (muon sends none on these
        // requests, but robustness is free).
        if let Some((_, len)) = headers.iter().find(|(k, _)| k == "content-length")
            && let Ok(len) = len.parse::<usize>()
        {
            let mut taken = 0;
            while taken < len {
                let n = stream.read(&mut chunk).expect("responder body read");
                if n == 0 {
                    break;
                }
                taken += n;
            }
        }
        seen.lock().unwrap().push(Recorded {
            method: method.clone(),
            path: path.clone(),
            headers,
        });

        // The responder enforces its own script: an unexpected exchange
        // fails the test here rather than deep inside muon's error
        // mapping.
        assert_eq!(
            method, step.method,
            "responder script mismatch on method (path {path})"
        );
        let bare_path = path.split('?').next().unwrap_or(&path);
        assert_eq!(
            bare_path, step.path,
            "responder script mismatch on path (method {method})"
        );

        // Serve.
        let mut out = format!(
            "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            step.status,
            step.body.len()
        );
        for (k, v) in &step.headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("\r\n");
        stream
            .write_all(out.as_bytes())
            .expect("responder write head");
        stream.write_all(&step.body).expect("responder write body");
        stream.flush().expect("responder flush");
    }

    fn find_terminator(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
    }

    // ===== the muon client against the loopback env ========================

    /// futures-IO over a tokio TCP stream: muon's `Socket` blanket-impls
    /// for any `AsyncRead + AsyncWrite + Unpin + Send + 'static`, and
    /// muon's own `HyperIo` adapts futures-IO to hyper's IO.
    struct TokioIo(tokio::net::TcpStream);

    impl muon::rt::AsyncRead for TokioIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let mut read_buf = tokio::io::ReadBuf::new(buf);
            match <tokio::net::TcpStream as tokio::io::AsyncRead>::poll_read(
                Pin::new(&mut self.get_mut().0),
                cx,
                &mut read_buf,
            ) {
                std::task::Poll::Ready(Ok(())) => {
                    std::task::Poll::Ready(Ok(read_buf.filled().len()))
                }
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        }
    }

    impl muon::rt::AsyncWrite for TokioIo {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            <tokio::net::TcpStream as tokio::io::AsyncWrite>::poll_write(
                Pin::new(&mut self.get_mut().0),
                cx,
                buf,
            )
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            <tokio::net::TcpStream as tokio::io::AsyncWrite>::poll_flush(
                Pin::new(&mut self.get_mut().0),
                cx,
            )
        }
        fn poll_close(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            <tokio::net::TcpStream as tokio::io::AsyncWrite>::poll_shutdown(
                Pin::new(&mut self.get_mut().0),
                cx,
            )
        }
    }

    /// Tokio-backed sleep + real clocks. The `Monotonic` marker below is
    /// the one scoped `unsafe` exception in this crate: muon's public
    /// surface cannot construct a `TimeCapabilities` without the empty
    /// marker assertion, every Proton downstream (muon's own test util,
    /// proton-vpn-rcrl, proton-vpn-local-agent) writes this exact impl,
    /// and `std::time::Instant` is monotonic by construction.
    #[derive(Debug, Clone)]
    struct TokioTime {
        at_start: Instant,
    }

    impl muon::rt::Sleep for TokioTime {
        type Sleep<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>>;
        fn sleep(&self, duration: Duration) -> Self::Sleep<'static> {
            Box::pin(tokio::time::sleep(duration))
        }
    }

    impl muon::rt::InstantFactory for TokioTime {
        type Instant = muon::rt::MuonInstant;
        fn now(&self) -> Self::Instant {
            muon::rt::MuonInstant::from_duration(Instant::now() - self.at_start)
        }
    }

    #[allow(unsafe_code)]
    unsafe impl muon::rt::Monotonic for TokioTime {}

    impl muon::rt::SystemTimeFactory for TokioTime {
        type SystemTime = muon::rt::MuonSystemTime;
        fn now(&self) -> Self::SystemTime {
            use muon::rt::SinceUnixEpoch as _;
            muon::rt::MuonSystemTime::since_unix_epoch(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock after epoch"),
            )
        }
    }

    #[derive(Debug, Clone, Default)]
    struct TokioDialer;

    impl muon::rt::TcpConnect for TokioDialer {
        type Err = std::io::Error;
        type Socket = TokioIo;
        async fn tcp_connect(&self, addr: std::net::SocketAddr) -> std::io::Result<Self::Socket> {
            Ok(TokioIo(tokio::net::TcpStream::connect(addr).await?))
        }
    }

    #[derive(Debug, Clone, Default)]
    struct TokioResolver;

    impl muon::rt::Resolve for TokioResolver {
        type Err = std::io::Error;
        async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, Self::Err> {
            let host = format!("{host}:0");
            tokio::task::spawn_blocking(move || {
                use std::net::ToSocketAddrs as _;
                host.to_socket_addrs()
                    .map(|addrs| addrs.map(|a| a.ip()).collect())
            })
            .await
            .map_err(std::io::Error::other)?
        }
    }

    #[derive(Debug, Clone)]
    struct TestOs {
        time: TokioTime,
        dialer: TokioDialer,
        resolver: TokioResolver,
    }

    impl muon::rt::OperatingSystem for TestOs {
        type Time = TokioTime;
        type TcpConnector = TokioDialer;
        type Resolver = TokioResolver;
        fn get_time_capabilities(&self) -> &Self::Time {
            &self.time
        }
        fn get_tcp_connector(&self) -> &Self::TcpConnector {
            &self.dialer
        }
        fn get_resolver(&self) -> &Self::Resolver {
            &self.resolver
        }
    }

    /// Deterministic test RNG: muon only derives transport jitter from
    /// it; a xorshift stream is plenty and keeps the crate free of a
    /// direct rand dependency.
    struct TestRng(u64);

    impl muon::rand::RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for chunk in dst.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    impl muon::rand::CryptoRng for TestRng {}

    /// Spawns muon's background tasks onto the ambient (dedicated
    /// runtime driven by the bridge).
    #[derive(Debug, Clone)]
    struct TokioExecutor;

    impl muon::rt::Spawn for TokioExecutor {
        fn spawn_obj(
            &self,
            future: muon::rt::FutureObj<'static, ()>,
        ) -> Result<(), muon::rt::SpawnError> {
            tokio::spawn(future);
            Ok(())
        }
    }

    /// The custom environment: one direct loopback `http://` server —
    /// `Scheme::Http` skips TLS entirely (spike memo Q3), and being the
    /// only direct server it is always the one chosen.
    #[derive(Debug, Clone)]
    struct LoopbackEnv {
        server: muon::common::Server,
    }

    impl muon::env::Env for LoopbackEnv {
        fn servers(&self, _version: &muon::app::AppVersion) -> Vec<muon::common::Server> {
            vec![self.server.clone()]
        }
        fn ar_pins(&self) -> Option<&muon::tls::pins::TlsPinSet> {
            None
        }
        fn api_pins(&self) -> Option<&muon::tls::pins::TlsPinSet> {
            None
        }
    }

    /// The ProtonWire SDK identity for the tests.
    fn test_sdk() -> muon::common::sdk::Sdk {
        muon::common::sdk::Sdk::new("protonwire", env!("CARGO_PKG_VERSION"))
            .expect("valid sdk identity")
    }

    /// Builds the adapter against the loopback env on a dedicated
    /// MULTI-thread runtime (`worker_threads(2)`). Multi-thread is
    /// load-bearing, not a preference: blocking a *current-thread*
    /// runtime via `Handle::block_on` from a foreign (non-runtime)
    /// thread deadlocks in the connector — the kernel completes the TCP
    /// handshake but nothing pumps the IO driver, so the connect future
    /// never wakes (spike-2026-08.md, "Adapter-facing facts for S4"),
    /// while `new_multi_thread` blocks correctly from the caller's
    /// thread. This is the canonical site S4's engine-runtime bridge
    /// copies — keep the two synchronized.
    fn adapter_against(port: u16) -> (MuonCatalog, tokio::runtime::Runtime) {
        // Opt-in transport tracing for seam debugging: silent unless
        // RUST_LOG is set (e.g. RUST_LOG=muon=trace).
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "off".into()),
            )
            .with_writer(std::io::stderr)
            .try_init();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test runtime");
        let server: muon::common::Server = format!("http://127.0.0.1:{port}/")
            .parse()
            .expect("loopback server url");
        let app = muon::App::new("linux-vpn@0.1.0").expect("app version");
        let env = muon::Environment::new_custom(LoopbackEnv { server });
        let sdk = test_sdk();

        let session = rt.block_on(async {
            // ER-17, aligned with production (the S4 adapter builds its
            // client with `RetryPolicy::never()`): without this the
            // default policy makes muon sleep-and-retry a 429/503 in
            // place, and the rate-limit fixtures would time out inside
            // the transport instead of delivering the classified
            // response. No automatic retries anywhere on this client.
            let retry = muon::common::RetryPolicy::default().never();
            let client = muon::Client::builder(app, env)
                .with_operating_system(
                    TestOs {
                        time: TokioTime {
                            at_start: Instant::now(),
                        },
                        dialer: TokioDialer,
                        resolver: TokioResolver,
                    },
                    TestRng(0x5EED),
                )
                .with_multi_thread_executor(TokioExecutor)
                .retry_policy(retry)
                .without_persistence::<()>()
                .without_cookie_store()
                .register_sdk(sdk.clone())
                .build()
                .expect("muon client");
            client
                .new_session_without_credentials(())
                .await
                .expect("session")
        });

        let handle = rt.handle().clone();
        let block_on: BlockOn = Arc::new(move |fut| handle.block_on(fut));
        (MuonCatalog::new(session, sdk, block_on), rt)
    }

    // ===== the tests ========================================================

    /// fetch(None): the full muon machinery — anonymous-session mint,
    /// then the conditional-less GET — returns the recorded fixture
    /// byte-for-byte with its ETag.
    #[test]
    fn fetch_changed_serves_the_recorded_fixture() {
        let (handle, port, seen) = spawn_responder(vec![
            Step::anon_session(),
            Step::catalog("200 OK", Some("\"rev-42\""), FIXTURE.as_bytes().to_vec()),
        ]);
        let (adapter, _rt) = adapter_against(port);

        let fetched = adapter.fetch(None).expect("changed fetch");
        handle.join().expect("responder thread");

        match fetched {
            CatalogFetch::Changed { etag, body } => {
                assert_eq!(etag.as_deref(), Some("\"rev-42\""));
                assert_eq!(
                    body,
                    FIXTURE.as_bytes(),
                    "the adapter must carry the raw upstream body for the store model"
                );
            }
            other => panic!("expected Changed, got {other:?}"),
        }

        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2, "mint + fetch: {requests:?}");
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].path, "/auth/v4/sessions");
        assert_eq!(requests[1].method, "GET");
        assert_eq!(requests[1].path, CATALOG_PATH);
        // The real transport's headers traveled: the app version and the
        // anonymous bearer muon minted and attached.
        assert!(
            requests[1].header("x-pm-appversion").is_some(),
            "muon app-version header missing: {:?}",
            requests[1].headers
        );
        assert_eq!(
            requests[1].header("authorization"),
            Some("Bearer anon-token"),
            "the minted anonymous session must author the catalog GET"
        );
        // No stored revision, no conditional header (FR-13B: absent
        // means absent — never a fabricated condition).
        assert_eq!(requests[1].header("if-none-match"), None);
    }

    /// fetch(Some(etag)): the condition travels as `If-None-Match`, the
    /// 304 passes muon's `ok()` and is classified NotModified.
    #[test]
    fn fetch_not_modified_round_trips_the_etag() {
        let (handle, port, seen) = spawn_responder(vec![
            Step::anon_session(),
            Step::catalog("304 Not Modified", None, Vec::new()),
        ]);
        let (adapter, _rt) = adapter_against(port);

        let fetched = adapter
            .fetch(Some("\"rev-42\""))
            .expect("conditional fetch");
        handle.join().expect("responder thread");

        assert_eq!(fetched, CatalogFetch::NotModified);

        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].header("if-none-match"),
            Some("\"rev-42\""),
            "the stored revision must travel as the condition"
        );
    }

    /// A dead endpoint surfaces as `ApiError::Transport` (stable-code
    /// territory; never a panic, never a fabricated empty catalog).
    #[test]
    fn fetch_maps_transport_failures() {
        // Bind, learn the port, drop the listener: nothing listens.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let (adapter, _rt) = adapter_against(port);

        match adapter.fetch(None) {
            Err(ApiError::Transport(report)) => {
                assert!(!report.is_empty());
            }
            other => panic!("expected Transport failure, got {other:?}"),
        }
    }

    /// S9 obligation (tracked since S6, the 429/503 wire-fixture lane):
    /// a 429 carrying `Retry-After` in the SECONDS form maps to
    /// [`ApiError::RateLimited`] with the parsed delay — the S7
    /// scheduler's suppression input. The loopback seam scripts the
    /// anonymous-session mint, then the 429.
    #[test]
    fn fetch_maps_429_with_retry_after_seconds() {
        let (handle, port, seen) = spawn_responder(vec![
            Step::anon_session(),
            Step::catalog_with_headers(
                "429 Too Many Requests",
                vec![("Retry-After", "120".to_owned())],
                Vec::new(),
            ),
        ]);
        let (adapter, _rt) = adapter_against(port);

        let err = adapter
            .fetch(None)
            .expect_err("429 must refuse, never fabricate");
        handle.join().expect("responder thread");

        match err {
            ApiError::RateLimited {
                retry_after_seconds,
            } => {
                assert_eq!(retry_after_seconds, Some(120));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }

        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2, "mint + refused fetch: {requests:?}");
        assert_eq!(requests[1].path, CATALOG_PATH);
    }

    /// S9 obligation (tracked since S6): a 503 with NO `Retry-After`
    /// still maps to [`ApiError::RateLimited`], with `None` for the
    /// delay — the scheduler's Q4 rule suppresses to the greatest-of
    /// floor when the API supplies no usable delay (a delay-less rate
    /// limit is still a rate limit).
    #[test]
    fn fetch_maps_503_without_retry_after() {
        let (handle, port, _seen) = spawn_responder(vec![
            Step::anon_session(),
            Step::catalog("503 Service Unavailable", None, Vec::new()),
        ]);
        let (adapter, _rt) = adapter_against(port);

        let err = adapter.fetch(None).expect_err("503 must refuse");
        handle.join().expect("responder thread");

        match err {
            ApiError::RateLimited {
                retry_after_seconds,
            } => {
                assert_eq!(retry_after_seconds, None);
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    /// The parse seam's unit pins (no wire needed): the seconds form
    /// parses; the HTTP-date form is REFUSED (disclosed: pinned Muon
    /// surfaces no date parser and fabricating one from a wall clock
    /// that may be wrong is worse than the floor — `None` still
    /// suppresses per Q4); whitespace tolerates nothing hostile; and
    /// the sec-tracked CLAMP bounds a hostile `Retry-After` at
    /// [`RETRY_AFTER_CEILING_SECONDS`].
    #[test]
    fn retry_after_parsing_and_the_availability_clamp() {
        // The seconds form.
        assert_eq!(parse_retry_after(Some("120")), Some(120));
        assert_eq!(parse_retry_after(Some("0")), Some(0));
        // Absent, empty, and the refused HTTP-date form all yield None.
        assert_eq!(parse_retry_after(None), None);
        assert_eq!(parse_retry_after(Some("")), None);
        assert_eq!(
            parse_retry_after(Some("Wed, 21 Oct 2026 07:28:00 GMT")),
            None,
            "the HTTP-date form is refused with a disclosure, never guessed"
        );
        assert_eq!(parse_retry_after(Some("soon")), None);
        // The clamp: a hostile delay must not suppress forever.
        assert_eq!(
            parse_retry_after(Some("1000000000")),
            Some(RETRY_AFTER_CEILING_SECONDS),
            "a hostile Retry-After is clamped at the ceiling, never honored verbatim"
        );
        assert_eq!(
            parse_retry_after(Some("18446744073709551616")),
            Some(RETRY_AFTER_CEILING_SECONDS),
            "a delay beyond u64's range clamps — it is certainly past the ceiling"
        );
        // A delay exactly at the ceiling survives; one past it clamps.
        assert_eq!(
            parse_retry_after(Some(&RETRY_AFTER_CEILING_SECONDS.to_string())),
            Some(RETRY_AFTER_CEILING_SECONDS)
        );
        assert_eq!(
            parse_retry_after(Some(&(RETRY_AFTER_CEILING_SECONDS + 1).to_string())),
            Some(RETRY_AFTER_CEILING_SECONDS)
        );
    }
}
