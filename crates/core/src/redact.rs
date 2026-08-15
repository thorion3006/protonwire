//! Secret redaction for logs (PRD FR-121, T-10, T-32 groundwork).
//!
//! Two layers:
//!
//! 1. [`SecretString`] — a zeroizing wrapper whose `Debug`/`Display` render
//!    as `[redacted]`, so accidental formatting never leaks the value.
//! 2. [`RedactingMakeWriter`] — a `tracing-subscriber` writer that scrubs
//!    registered secret *values* from every emitted line, including values
//!    that dependencies stringify into messages (the Muon/ProTUN leak path
//!    called out by FR-7P).
//!
//! Registered values are tracked by lifetime: an ALIVE secret is always
//! scrubbable and dead ones fall out of the registry (no count cap can age
//! a live token out of scrubbing — Codex PR review finding 12), and every
//! value is zeroized when its last handle drops.

use std::borrow::Cow;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

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
fn register(value: &str) -> Arc<Zeroizing<String>> {
    let secret = Arc::new(Zeroizing::new(value.to_owned()));
    if value.len() >= MIN_SECRET_LEN {
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
    /// Creates a secret and registers its value for log scrubbing.
    pub fn new(value: impl Into<String>) -> Self {
        Self(register(&value.into()))
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
/// default).
pub fn init_tracing(env_filter: bool) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let fmt_layer =
        tracing_subscriber::fmt::layer().with_writer(RedactingMakeWriter::new(std::io::stdout));
    let subscriber = tracing_subscriber::registry().with(fmt_layer);
    if env_filter {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        subscriber.with(filter).init();
    } else {
        subscriber.init();
    }
}

/// Initializes global tracing with redaction and a caller-supplied default
/// level that applies when `RUST_LOG` is unset.
pub fn init_tracing_filtered(default_level: &str) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer().with_writer(RedactingMakeWriter::new(std::io::stdout)),
        )
        .with(filter)
        .init();
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
        let _short = register_secret("value");
        let _long = register_secret("secretvalue");
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
