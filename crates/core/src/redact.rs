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
//! Registered values are held only to power scrubbing, are capped in count,
//! and are zeroized on drop.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::Mutex;

use zeroize::Zeroizing;

/// Placeholder substituted for secret values.
pub const REDACTED: &str = "[redacted]";

/// Minimum length for a registrable secret; shorter strings scrub too
/// aggressively (for example a 2-char fragment would mangle ordinary words).
const MIN_SECRET_LEN: usize = 4;

/// Maximum number of retained secrets; registration beyond this evicts the
/// oldest.
const MAX_SECRETS: usize = 256;

static REGISTRY: Mutex<VecDeque<Zeroizing<String>>> = Mutex::new(VecDeque::new());

/// Registers a secret value for scrubbing.
pub fn register_secret(value: &str) {
    if value.len() < MIN_SECRET_LEN {
        return;
    }
    let mut registry = REGISTRY.lock().expect("secret registry lock");
    if registry.len() >= MAX_SECRETS {
        registry.pop_front();
    }
    registry.push_back(Zeroizing::new(value.to_owned()));
}

/// Replaces every occurrence of a registered secret with [`REDACTED`].
pub fn scrub(input: &str) -> Cow<'_, str> {
    let registry = REGISTRY.lock().expect("secret registry lock");
    let mut output: Option<String> = None;
    for secret in registry.iter() {
        if input.contains(secret.as_str()) {
            let target = output.as_deref().unwrap_or(input);
            output = Some(target.replace(secret.as_str(), REDACTED));
        }
    }
    output.map(Cow::Owned).unwrap_or(Cow::Borrowed(input))
}

/// A zeroizing, redacting-on-format secret string.
#[derive(Clone)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Creates a secret and registers its value for log scrubbing.
    pub fn new(value: impl Into<String>) -> Self {
        let value: String = value.into();
        register_secret(&value);
        Self(Zeroizing::new(value))
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
        let scrubbed = scrub(&String::from_utf8_lossy(&self.line));
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

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(RedactingMakeWriter::new(std::io::stdout));
    let subscriber = tracing_subscriber::registry().with(fmt_layer);
    if env_filter {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        subscriber.with(filter).init();
    } else {
        subscriber.init();
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
        register_secret("hunter2supersecret");
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
        register_secret("ab");
        assert_eq!(scrub("abc"), "abc");
    }

    #[test]
    fn writer_scrubs_full_lines() {
        let buffer = SharedBuffer::default();
        let mut writer = LineScrubWriter {
            inner: buffer.clone(),
            line: Vec::new(),
        };
        register_secret("s3cr3t-value");
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
        register_secret("part-secret-99");
        writer.write_all(b"partial part-secret-99").unwrap();
        assert!(buffer.string().is_empty());
        writer.flush().unwrap();
        assert!(buffer.string().contains("[redacted]"));
    }
}
