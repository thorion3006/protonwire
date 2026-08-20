//! The Muon engine runtime (M2 S4): the tokio-backed operating system,
//! executor, and synchronous bridge the adapter drives Muon's async
//! hyper transport through.
//!
//! Muon's client is async over injectable `muon::rt` traits (spike memo
//! "Adapter-facing facts"): the pinned crate ships no runtime. This
//! module is the production runtime half of the two-layer seam decision
//! (spike memo Q3): the ProtonWire traits stay synchronous (the daemon's
//! trust boundary, M1 posture — no async runtime inside the IPC
//! threads), and every adapter call crosses [`EngineBridge`] onto a
//! dedicated engine runtime owned by the adapter, so tokio enters this
//! process exactly once, inside this component, isolated from the IPC
//! threads by the method boundary (the M1 security posture: "ProTUN/
//! Muon will bring tokio into the daemon in M2/M4, isolated from the
//! IPC threads by channels").
//!
//! The socket, dialer, resolver, and spawner are tokio-backed exactly as
//! Muon's own examples integrate the crate; the futures-IO/tokio-IO
//! boundary is bridged by hand below (safe `ReadBuf` plumbing — the
//! lockfile has no `async-compat`, and adopting it would be a new
//! package for two dozen lines).
//!
//! Dependency note (stdlib-first policy): `tokio`, `rand_chacha`, and
//! `getrandom` are declared here directly for M2 exactly as the spike
//! record anticipated ("tokio and reqwest appear transitively; they are
//! declared centrally when M2+ code calls them directly"); every one is
//! already a lockfile package via the pinned engines, so no new package
//! enters the resolution.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::time::Instant;

/// Bridges the synchronous trust boundary onto the engine runtime: runs
/// `future` to completion, blocking the caller.
///
/// The adapter's trait methods are synchronous; every Muon call they
/// make crosses this seam. Injected at construction (the repo's
/// seam-injection idiom) so tests drive a dedicated runtime and the
/// daemon can share its own; the production implementation is
/// [`TokioBridge`].
pub trait EngineBridge: Send + Sync + 'static {
    /// Blocks on `future` until it yields `T`.
    fn block_on<T: Send + 'static>(&self, future: Pin<Box<dyn Future<Output = T> + Send>>) -> T;
}

/// The production bridge: a dedicated multi-thread tokio runtime owned
/// by the adapter. Workers drive the reactor (IO and timers) while the
/// calling IPC thread blocks in [`EngineBridge::block_on`], so blocking
/// never happens on a runtime worker and the daemon's synchronous
/// surface stays synchronous.
#[derive(Debug)]
pub struct TokioBridge {
    runtime: tokio::runtime::Runtime,
}

impl TokioBridge {
    /// Creates the dedicated engine runtime (two workers by default:
    /// enough to drive IO while a request future is polled).
    ///
    /// Deliberately a MULTI-thread runtime: blocking a current-thread
    /// runtime from a foreign (IPC) thread deadlocks Muon's connector —
    /// the kernel-level connect completes but the connect future never
    /// wakes (reproduced with transport tracing by the S6 wire seam).
    /// Workers must be free to drive the reactor while the caller
    /// blocks.
    ///
    /// # Errors
    /// Propagates the tokio runtime-build failure (thread/resource
    /// exhaustion).
    pub fn dedicated() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        Ok(Self { runtime })
    }

    /// The runtime handle (spawn onto the engine runtime from async
    /// contexts).
    #[must_use]
    pub fn handle(&self) -> &tokio::runtime::Handle {
        self.runtime.handle()
    }
}

impl EngineBridge for TokioBridge {
    fn block_on<T: Send + 'static>(&self, future: Pin<Box<dyn Future<Output = T> + Send>>) -> T {
        self.runtime.handle().block_on(future)
    }
}

// ---------------------------------------------------------------------------
// futures-IO over a tokio TCP stream
// ---------------------------------------------------------------------------

/// A tokio `TcpStream` as muon's `Socket` (futures `AsyncRead`/
/// `AsyncWrite`). `poll_write`/`poll_flush`/`poll_close` have identical
/// shapes in both traits; `poll_read` is bridged through tokio's
/// `ReadBuf` — entirely safe plumbing, no uninitialized reads escape.
#[derive(Debug)]
pub struct TokioIo(pub tokio::net::TcpStream);

impl muon::rt::AsyncRead for TokioIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut read_buf = tokio::io::ReadBuf::new(buf);
        match <tokio::net::TcpStream as tokio::io::AsyncRead>::poll_read(
            Pin::new(&mut self.get_mut().0),
            cx,
            &mut read_buf,
        ) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl muon::rt::AsyncWrite for TokioIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        <tokio::net::TcpStream as tokio::io::AsyncWrite>::poll_write(
            Pin::new(&mut self.get_mut().0),
            cx,
            buf,
        )
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        <tokio::net::TcpStream as tokio::io::AsyncWrite>::poll_flush(
            Pin::new(&mut self.get_mut().0),
            cx,
        )
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        <tokio::net::TcpStream as tokio::io::AsyncWrite>::poll_shutdown(
            Pin::new(&mut self.get_mut().0),
            cx,
        )
    }
}

// ---------------------------------------------------------------------------
// Time, dialer, resolver, executor, OS, PRNG
// ---------------------------------------------------------------------------

/// Tokio-backed time: real sleeps (`tokio::time`), real monotonic
/// instants (`std::time::Instant`), real wall clock.
///
/// The `Monotonic` marker below is the one scoped `unsafe` exception in
/// this crate's production code (mirroring the test-local exception the
/// S6 wire seam already disclosed): muon 2.6.1's public surface cannot
/// construct a `TimeCapabilities` without the empty marker assertion
/// (`InstantFactory: Monotonic`), every Proton downstream integrator
/// writes this exact impl (pvpnclient `muon.rs:52`, muon's own test
/// util, proton-vpn-rcrl, proton-vpn-local-agent), and the marker is
/// vacuously sound here: the only clock behind it is
/// `std::time::Instant`, which is monotonic by construction and is not
/// a realtime source. No memory unsafety is reachable through an empty
/// marker trait; the assertion it demands is a true statement about
/// `std`.
#[derive(Debug, Clone)]
pub struct TokioTime {
    at_start: Instant,
}

impl Default for TokioTime {
    fn default() -> Self {
        Self {
            at_start: Instant::now(),
        }
    }
}

impl muon::rt::Sleep for TokioTime {
    type Sleep<'a>
        = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>>
    where
        Self: 'a;

    fn sleep(&self, duration: core::time::Duration) -> Self::Sleep<'static> {
        Box::pin(tokio::time::sleep(duration))
    }
}

impl muon::rt::InstantFactory for TokioTime {
    type Instant = muon::rt::MuonInstant;

    fn now(&self) -> Self::Instant {
        muon::rt::MuonInstant::from_duration(Instant::now() - self.at_start)
    }
}

// SAFETY: see the struct documentation — the clock source is
// std::time::Instant, monotonic by construction, never a realtime clock.
#[allow(unsafe_code)]
unsafe impl muon::rt::Monotonic for TokioTime {}

impl muon::rt::SystemTimeFactory for TokioTime {
    type SystemTime = muon::rt::MuonSystemTime;

    fn now(&self) -> Self::SystemTime {
        use muon::rt::SinceUnixEpoch as _;
        // Pre-epoch clock (dead RTC, rust Low S4 round): zero (the
        // Unix epoch) rather than panicking inside the transport —
        // expiry arithmetic degrades, the daemon does not take a
        // panic path over a wrong wall clock.
        muon::rt::MuonSystemTime::since_unix_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default(),
        )
    }
}

/// The tokio TCP dialer.
#[derive(Debug, Clone, Default)]
pub struct TokioDialer;

impl muon::rt::TcpConnect for TokioDialer {
    type Err = std::io::Error;
    type Socket = TokioIo;

    async fn tcp_connect(&self, addr: SocketAddr) -> std::io::Result<Self::Socket> {
        Ok(TokioIo(tokio::net::TcpStream::connect(addr).await?))
    }
}

/// The system resolver, run on the runtime's blocking pool (getaddrinfo
/// is blocking).
#[derive(Debug, Clone, Default)]
pub struct TokioResolver;

impl muon::rt::Resolve for TokioResolver {
    type Err = std::io::Error;

    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, Self::Err> {
        let host = format!("{host}:0");
        tokio::task::spawn_blocking(move || {
            use std::net::ToSocketAddrs as _;
            host.to_socket_addrs()
                .map(|addrs| addrs.map(|addr| addr.ip()).collect())
        })
        .await
        .map_err(std::io::Error::other)?
    }
}

/// The tokio-backed operating system Muon's hyper builder requires.
#[derive(Debug, Clone, Default)]
pub struct TokioOs {
    time: TokioTime,
    dialer: TokioDialer,
    resolver: TokioResolver,
}

impl muon::rt::OperatingSystem for TokioOs {
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

/// Spawns Muon's background tasks onto the engine runtime.
#[derive(Debug, Clone)]
pub struct TokioSpawner;

impl muon::rt::Spawn for TokioSpawner {
    fn spawn_obj(
        &self,
        future: muon::rt::FutureObj<'static, ()>,
    ) -> Result<(), muon::rt::SpawnError> {
        tokio::spawn(future);
        Ok(())
    }
}

/// The transport PRNG seed source: the OS CSPRNG (`getrandom` — already
/// a lockfile transitive and the plan's chosen promotion for M2 RNG
/// needs), seeding muon's own `ChaCha20Rng` derivation.
///
/// # Errors
/// Propagates the OS entropy failure.
pub fn os_prng() -> std::io::Result<rand_chacha::ChaCha20Rng> {
    use muon::rand::SeedableRng;
    let mut seed = <rand_chacha::ChaCha20Rng as SeedableRng>::Seed::default();
    getrandom::getrandom(&mut seed)?;
    Ok(rand_chacha::ChaCha20Rng::from_seed(seed))
}
