//! Credential input sources — the INPUT half of the credential
//! input/writable-store separation (M2 S5a; PRD FR-7F, SEC-16B, T-12).
//!
//! ProtonWire separates WHERE credentials enter from WHERE (whether) they
//! are persisted (SEC-3: "Input source and writable store are separate
//! state"). This module owns the input half only: the S3 config
//! vocabulary `account.credential_input_source` (`interactive|systemd`)
//! resolved against real types. The writable half (keyring/TPM2/
//! encrypted-local, `auto` resolution, persistence health) is S5b/S5c;
//! TPM2 and full encrypted-local stores are post-M2 (m2-plan decision 2).
//!
//! * [`CredentialSource::Interactive`] — values arrive eventually via the
//!   S9 IPC surface. S5a models that as an INJECTED PROVIDER CLOSURE
//!   ([`InteractiveProvider`]); there is no prompt code in this unit.
//! * [`CredentialSource::Systemd`] — read-only import from
//!   `$CREDENTIALS_DIRECTORY` per systemd `LoadCredential=` conventions
//!   (systemd.exec(5)): each credential is a plain `<name>` file, read
//!   fully, never modified. FR-7F: systemd credentials are immutable
//!   service-lifetime input — consumed, never written back, never a
//!   writable backend. There is NO write-back path in this unit at all
//!   (no save/store/remove API exists); "migrate to loadcredential" is
//!   invalid by construction here and is refused textually at the S9 CLI
//!   (T-12). The transactional idempotent import into a writable store
//!   (FR-7JC, stale-replay refusal) is S5b.
//!
//! # The peer-secret boundary (S1/S4 contract)
//!
//! Every value crossing the source boundary enters through
//! [`SecretBoundary::ingress`] — in production, `protonwire_core::redact::
//! peer_secret` (M1 security finding 10): credential values are external
//! input and must never touch the global scrub registry. This crate
//! cannot name that type: `protonwire-core` depends on `protonwire-store`
//! (the reverse edge would be a dependency cycle), so the boundary is an
//! injected collaborator — the house seam-injection idiom (CONTRIBUTING
//! "Concurrent lanes" rule 7). The production wiring is one impl in the
//! consumer lane and lands with S5b/S9 (this unit must not wire the
//! daemon):
//!
//! ```text
//! // in the daemon lane, once: PeerSecret IS the boundary
//! impl protonwire_store::credential_input::SecretBoundary
//!     for protonwire_core::redact::PeerSecret
//! {
//!     fn ingress(value: String) -> Self {
//!         protonwire_core::redact::peer_secret(value)
//!     }
//!     fn expose(&self) -> &str {
//!         protonwire_core::redact::PeerSecret::expose(self)
//!     }
//! }
//! ```
//!
//! The interactive provider returns the same secret type: values arriving
//! over the S9 IPC surface are wrapped at THAT wire boundary (the S4
//! adapter's contract), so the provider hands over already-guarded
//! values. `expose()` is called at exactly TWO deliberate consumer
//! sites, both gates rather than uses of the value as data: the
//! interactive arm's blankness check in [`CredentialSource::read`]
//! (fail-closed symmetry with the systemd arm's empty-file refusal —
//! a blank is not a credential), and [`parse_session_envelope`], the
//! FR-7C envelope bridge whose eventual caller is the S4 MuonAuth
//! adapter's persistence facade.
//!
//! # Fail-closed (every refusal is typed, never a blank/partial value)
//!
//! A missing credential file, an unreadable file, an empty value (a
//! zero-byte credential file, or a blank handed back by the interactive
//! surface — both arms refuse blanks), an
//! oversized value, a non-UTF-8 value, a traversal-shaped credential
//! name, a symlink or subdirectory where a credential file should be, a
//! leaf with group/world permission bits, an untrusted (writable or
//! non-root-owned) credentials directory — each refuses with a typed
//! [`CredentialInputError`]. Error payloads carry names, paths, sizes,
//! and modes; they never carry the value bytes (a `NotUtf8` refusal
//! deliberately discards `FromUtf8Error`, whose Display embeds the
//! offending bytes, and an envelope parse refusal reduces serde's error
//! to its category and line/column — serde's Display embeds the
//! offending value verbatim), and the value bytes themselves live in
//! zeroizing storage from the read to the ingress seam.
//!
//! # Trust root: the credentials directory itself
//!
//! The fs_trust walker ([`crate::fs_trust::verify_trusted_path`]) is
//! applied with the trust root AT `$CREDENTIALS_DIRECTORY`, not `/` (the
//! system-config rule) and not `/var/lib/protonwire` (daemon-managed
//! persistent state, a different trust domain owned by the writable-store
//! half). Why the unit-scoped root is correct: systemd (PID 1) creates
//! `/run/credentials/<unit>/` fresh at service start on a tmpfs, owned
//! `root:root`, mode `0700`, scoped to the unit and its lifetime — the
//! directory IS the delivery boundary systemd guarantees. Walking above
//! it would add components ProtonWire has no policy for (and no added
//! guarantee — the tree above is PID 1's, not ours) while risking false
//! rejections; walking the boundary itself plus every leaf inside it
//! rejects exactly the defects that matter here: a planted or replaced
//! credential (non-root owner), a tamperable tree (group/world write),
//! and laundered paths (symlinks — SEC-16B: "opened without path
//! traversal").
//!
//! Check order inside [`SystemdCredentialDirectory::read`]: name
//! validation, then ONE pinned `open(2)` (`O_NOFOLLOW` — a symlinked
//! leaf fails at open with `ELOOP`, mapped to the typed symlink
//! refusal), then the `fstat` gates on THAT descriptor (regular-file
//! type, owner-only mode, size — all before a single byte is read),
//! then the size-bounded read FROM the descriptor, then content gates,
//! then the ancestor trust walk, then ingress (S5a sec P3, landed S5b:
//! the descriptor is the inode every gate approved, so a path swap
//! between gate and read changes nothing the gates saw). Content is
//! inspected before the walk so the fail-closed matrix is provable on
//! non-root development runners (the walker's ownership pass would
//! otherwise shadow every content defect on a user-owned tree). This
//! does not weaken the guarantee: nothing leaves `read` before the
//! walk passes — and the walk was already happens-before-use, not
//! atomic (`fs_trust.rs`).
//!
//! Value transit is ZEROIZING end to end (S5a sec P2, landed S5b): the
//! bytes read live in `Zeroizing<Vec<u8>>`, the UTF-8 string in
//! `Zeroizing<String>`, and the ingress seam MOVES the allocation out
//! of transit (`mem::take`) — no refusal path, and no intermediate
//! copy, ever drops plain credential bytes (the `FromUtf8Error` owns
//! its offending bytes, so that arm re-captures them into zeroizing
//! storage before discarding them).

use std::collections::BTreeMap;
use std::io;
use std::io::Read as _;
use std::marker::PhantomData;
use std::mem;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use zeroize::Zeroizing;

use crate::config::AccountSection;
use crate::config::CredentialInputSource as ConfiguredCredentialSource;
use crate::fs_trust::FsTrustError;
use crate::fs_trust::MissingLeaf;
use crate::fs_trust::verify_trusted_path;
use crate::session::SESSION_SCHEMA_VERSION;
use crate::session::SessionEnvelope;
use crate::session::SessionEnvelopeError;

/// The environment variable systemd points at the per-unit credentials
/// directory (`LoadCredential=`/`LoadCredentialEncrypted=`,
/// systemd.exec(5)). Read at resolution time; absent means the daemon is
/// not running under systemd with credentials provisioned — a hard
/// refusal when the config names the systemd source (FR-7J).
pub const CREDENTIALS_DIRECTORY_VAR: &str = "CREDENTIALS_DIRECTORY";

/// The short name of the preferred versioned session envelope credential
/// (FR-7F): the `session` key of `account.systemd_credential_names`.
/// A session envelope is preferred over the username/password bootstrap
/// pair.
pub const SESSION_SHORT_NAME: &str = "session";

/// Size ceiling for one credential value: 64 KiB.
///
/// The largest legitimate credential is the FR-7C session envelope —
/// `crate::session::MAX_SESSION_BYTES` caps that document at 64 KiB
/// ("a few hundred bytes of wrapped credentials; generous headroom") —
/// and usernames, passwords, and tokens are far smaller. Matching that
/// ceiling here means the preferred credential always fits the input
/// side, keeps one consistent bound across the input/store seam, and
/// satisfies SEC-16B ("size-bounded") without reading a hostile or
/// corrupted file whole into memory.
pub const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

/// Group and world permission bits (read, write, or execute beyond the
/// owner). A credential leaf must be owner-only: systemd provisions
/// credentials mode `0400` inside a `0700` directory, and group/world
/// READ on a credential file is disclosure, not just tampering surface.
const LEAF_BEYOND_OWNER: u32 = 0o077;

/// `open(2)` flags for the pinned credential read (S5a sec P3, landed
/// S5b), from nix's typed `OFlag` (std's `custom_flags` takes raw bits
/// and names none; hand-rolled syscall constants are exactly what this
/// repo's stdlib-first policy prefers a dependency over).
///
/// `O_NOFOLLOW` makes a symlinked leaf fail AT OPEN (`ELOOP`) — the
/// link itself is the defect (SEC-16B), never a target to follow.
/// `O_NONBLOCK` keeps a hostile FIFO planted where a credential file
/// should be from hanging the open; on the regular files the fstat gate
/// below requires it has no effect on `read(2)`.
fn pinned_open_flags() -> i32 {
    (nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits()
}

/// Opens `path` once, pinned: read-only with [`pinned_open_flags`]. The
/// returned descriptor is the inode every later gate and read uses —
/// see [`SystemdCredentialDirectory::read`].
pub(crate) fn open_pinned(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(pinned_open_flags())
        .open(path)
}

/// Size-bounded read FROM THE PINNED DESCRIPTOR into zeroizing storage
/// (S5a sec P2): credential bytes are secret material from the moment
/// they exist, refusal paths included — every discard below drops a
/// `Zeroizing`, never a plain buffer. Reads at most `cap + 1` bytes so
/// an over-cap file is detected without reading it whole.
pub(crate) fn read_bounded(file: &std::fs::File, cap: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The peer-secret boundary the input half is generic over.
///
/// Production implements this for
/// `protonwire_core::redact::PeerSecret` in the consumer lane (see the
/// module documentation — this crate cannot name that type because
/// `protonwire-core` depends on `protonwire-store`); the two methods are
/// exactly `peer_secret` and `PeerSecret::expose`, so the seam cannot
/// drift from the S1/S4 contract.
pub trait SecretBoundary: Sized {
    /// Wraps a raw credential value into guarded storage at the source
    /// boundary. The ONLY sanctioned way a value enters this module's
    /// output (the S1/S4 gate: peer-derived values never enter the
    /// global scrub registry).
    fn ingress(value: String) -> Self;

    /// Read access for the deliberate consumer. Within this crate that is
    /// exactly two gate sites: the interactive arm's blankness check in
    /// [`CredentialSource::read`] and [`parse_session_envelope`];
    /// anywhere else it belongs to the caller that owns the secret.
    fn expose(&self) -> &str;
}

/// The injected interactive provider (the S9 IPC seam, S5a model): given
/// a credential short name, yields the already-guarded value or `None`
/// when the surface has no value (user decline, no prompt flow). This is
/// a closure, NOT a prompt: no interactive input is implemented in this
/// unit.
pub type InteractiveProvider<S> = Arc<dyn Fn(&str) -> Option<S> + Send + Sync>;

/// A live credential input source, resolved from the S3 vocabulary
/// `account.credential_input_source` (exactly the two sources that
/// vocabulary names; unknown spellings already fail at config parse —
/// S3 — so the vocabulary-to-source mapping is total).
pub enum CredentialSource<S> {
    /// Values arrive via the S9 IPC surface, modeled as an injected
    /// provider closure.
    Interactive {
        /// The S9 seam: short name -> guarded value, or `None`.
        provider: InteractiveProvider<S>,
    },
    /// Read-only import from the systemd credentials directory.
    Systemd(SystemdCredentialDirectory<S>),
}

/// Manual because the provider closure carries no `Debug`; renders the
/// ARM only — never a credential value or provider state.
impl<S> std::fmt::Debug for CredentialSource<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Interactive { .. } => "CredentialSource::Interactive",
            Self::Systemd(_) => "CredentialSource::Systemd",
        })
    }
}

/// The systemd credentials directory (read-only input, FR-7F/SEC-16B):
/// `$CREDENTIALS_DIRECTORY` plus the configured short-name ->
/// credential-name map (`account.systemd_credential_names`).
pub struct SystemdCredentialDirectory<S> {
    directory: PathBuf,
    names: BTreeMap<String, String>,
    _secret: PhantomData<fn() -> S>,
}

impl<S> SystemdCredentialDirectory<S> {
    /// Builds the source over an explicit directory and name map.
    ///
    /// No filesystem access happens here; every trust and content check
    /// runs per-read, fail-closed.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>, names: BTreeMap<String, String>) -> Self {
        Self {
            directory: directory.into(),
            names,
            _secret: PhantomData,
        }
    }

    /// Builds the source from the systemd-provisioned environment
    /// (`$CREDENTIALS_DIRECTORY`) and the configured names.
    ///
    /// # Errors
    /// [`CredentialInputError::NoCredentialsDirectory`] when the
    /// variable is absent — a configured systemd source with no
    /// systemd behind it is a misdeployment, refused rather than
    /// silently blank (FR-7J) — and
    /// [`CredentialInputError::EmptyCredentialsDirectory`] when it is
    /// set but empty (a broken deployment, distinct from absent).
    pub fn from_env(account: &AccountSection) -> Result<Self, CredentialInputError> {
        let directory = resolve_systemd_directory(
            std::env::var_os(CREDENTIALS_DIRECTORY_VAR)
                .as_deref()
                .map(Path::new),
        )?;
        Ok(Self::new(
            directory,
            account.systemd_credential_names.clone(),
        ))
    }

    /// The credentials directory (the fs_trust trust root).
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Resolves a short name to its credential file path, refusing
    /// traversal-shaped names (SEC-16B: credentials are opened "without
    /// path traversal" — a credential name is a single plain file name
    /// inside the trust root, never a path).
    ///
    /// # Errors
    /// [`CredentialInputError::NameNotConfigured`] when the short name
    /// has no configured mapping; [`CredentialInputError::
    /// BadCredentialName`] when the mapped credential name is not a
    /// plain file name.
    pub fn credential_path(&self, short_name: &str) -> Result<PathBuf, CredentialInputError> {
        let (_name, path) = self.resolve(short_name)?;
        Ok(path)
    }

    /// The shared resolution: short name -> (credential name, path).
    fn resolve(&self, short_name: &str) -> Result<(&str, PathBuf), CredentialInputError> {
        let name =
            self.names
                .get(short_name)
                .ok_or_else(|| CredentialInputError::NameNotConfigured {
                    name: short_name.to_owned(),
                })?;
        if !is_plain_file_name(name) {
            return Err(CredentialInputError::BadCredentialName {
                name: name.to_owned(),
            });
        }
        Ok((name, self.directory.join(name)))
    }
}

impl<S: SecretBoundary> SystemdCredentialDirectory<S> {
    /// Reads one credential by its configured short name and returns it
    /// through the peer-secret ingress. Fully fail-closed — see the
    /// module documentation for the refusal matrix and check order.
    ///
    /// The read is FD-PINNED (S5a sec P3, landed S5b): the file is
    /// opened ONCE with `O_NOFOLLOW` (a symlinked leaf fails at open —
    /// `ELOOP`, mapped to the typed symlink refusal), every gate that
    /// matters for the bytes (regular-file type, owner-only mode, size)
    /// runs on the `fstat` OF THAT DESCRIPTOR, and the bytes are read
    /// from the same descriptor — a path swap between the gates and the
    /// read changes nothing the gates approved.
    ///
    /// # Errors
    /// Every refusal is typed: see [`CredentialInputError`]. Never a
    /// partial or blank value.
    pub fn read(&self, short_name: &str) -> Result<S, CredentialInputError> {
        let (name, path) = self.resolve(short_name)?;
        // 1. Open once, pinned: `O_NOFOLLOW` refuses a symlinked leaf AT
        //    OPEN (ELOOP → the typed symlink refusal — the link is the
        //    defect, its target never consulted); absent is the typed
        //    Missing; anything else is Unreadable.
        let file = match open_pinned(&path) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(CredentialInputError::Missing {
                    name: name.to_owned(),
                    path: path.clone(),
                });
            }
            Err(source) if source.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32) => {
                return Err(CredentialInputError::Untrusted(FsTrustError::Symlink {
                    path: path.clone(),
                }));
            }
            Err(source) => {
                return Err(CredentialInputError::Unreadable {
                    name: name.to_owned(),
                    path: path.clone(),
                    source,
                });
            }
        };
        // 2. fstat THE DESCRIPTOR — the inode the read below will come
        //    from. Type (a subdirectory or FIFO where a credential file
        //    should be), owner-only mode (disclosure-class: beats any
        //    content defect), then size (stat-first: a hostile file is
        //    refused on size before a single byte is read).
        let leaf = file
            .metadata()
            .map_err(|source| CredentialInputError::Unreadable {
                name: name.to_owned(),
                path: path.clone(),
                source,
            })?;
        if !leaf.is_file() {
            return Err(CredentialInputError::Untrusted(
                FsTrustError::NotARegularFile { path: path.clone() },
            ));
        }
        let mode = leaf.mode() & 0o777;
        if mode & LEAF_BEYOND_OWNER != 0 {
            return Err(CredentialInputError::ExcessivePermission {
                name: name.to_owned(),
                path: path.clone(),
                mode,
            });
        }
        if leaf.len() > MAX_CREDENTIAL_BYTES as u64 {
            return Err(CredentialInputError::Oversized {
                name: name.to_owned(),
                path: path.clone(),
                size: leaf.len(),
                cap: MAX_CREDENTIAL_BYTES,
            });
        }
        // 3. Read from the pinned descriptor into ZEROIZING storage
        //    (S5a sec P2): the bytes are credential material from the
        //    first byte, on refusal paths included. Belt-and-braces
        //    post-read cap: the file may have grown since the fstat.
        let mut bytes = read_bounded(&file, MAX_CREDENTIAL_BYTES).map_err(|source| {
            CredentialInputError::Unreadable {
                name: name.to_owned(),
                path: path.clone(),
                source,
            }
        })?;
        if bytes.len() > MAX_CREDENTIAL_BYTES {
            return Err(CredentialInputError::Oversized {
                name: name.to_owned(),
                path: path.clone(),
                size: leaf.len(),
                cap: MAX_CREDENTIAL_BYTES,
            });
        }
        if bytes.is_empty() {
            return Err(CredentialInputError::Empty {
                name: name.to_owned(),
                path: path.clone(),
            });
        }
        // 4. Credentials are text (envelopes are JSON, usernames and
        //    passwords are strings). `FromUtf8Error` OWNS the offending
        //    bytes, so on the refusal path they are re-captured into
        //    zeroizing storage before being dropped (its Display also
        //    embeds them — that arm predates this one).
        let mut value = match String::from_utf8(mem::take(&mut *bytes)) {
            Ok(value) => Zeroizing::new(value),
            Err(error) => {
                let _recovered = Zeroizing::new(error.into_bytes());
                return Err(CredentialInputError::NotUtf8 {
                    name: name.to_owned(),
                    path: path.clone(),
                });
            }
        };
        // 5. The authoritative trust walk: the credentials directory is
        //    the trust root. The fd pins the LEAF (gates 2-4 all ran on
        //    its inode); this walk covers the leaf's PATH and every
        //    ancestor to the root — no group/world write, root-owned.
        //    Nothing has left this function yet — a refusal here
        //    discards the zeroizing transit bytes.
        match verify_trusted_path(&path, &self.directory, MissingLeaf::Reject) {
            Ok(()) => {}
            // Only reachable through a delete race with step 1; report
            // it as the missing credential it is, not an inspection
            // failure.
            Err(FsTrustError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Err(CredentialInputError::Missing {
                    name: name.to_owned(),
                    path: path.clone(),
                });
            }
            Err(error) => return Err(error.into()),
        }
        // 6. Ingress at the seam: the value MOVES out of zeroizing
        //    transit into the guarded boundary type (`mem::take` leaves
        //    an empty string behind, zeroized on drop — no unzeroized
        //    copy is ever made).
        Ok(S::ingress(mem::take(&mut *value)))
    }
}

impl<S: SecretBoundary> CredentialSource<S> {
    /// Resolves the S3 vocabulary against the live environment: the
    /// production entry point, reading `$CREDENTIALS_DIRECTORY` for the
    /// systemd arm.
    ///
    /// # Errors
    /// [`CredentialInputError::NoCredentialsDirectory`] when the
    /// vocabulary names the systemd source and the variable is absent;
    /// [`CredentialInputError::EmptyCredentialsDirectory`] when it is
    /// set but empty.
    pub fn resolve(
        vocabulary: ConfiguredCredentialSource,
        account: &AccountSection,
        provider: InteractiveProvider<S>,
    ) -> Result<Self, CredentialInputError> {
        let directory = std::env::var_os(CREDENTIALS_DIRECTORY_VAR).map(PathBuf::from);
        Self::resolve_in(vocabulary, account, directory.as_deref(), provider)
    }

    /// The testable resolution seam: the credentials directory is
    /// injected instead of read from the environment (edition-2024
    /// `set_var` is `unsafe`, and the workspace denies `unsafe_code`, so
    /// tests cannot stage the variable; they stage the directory).
    ///
    /// Total over the vocabulary: `interactive` -> the injected
    /// provider; `systemd` -> the given directory (or a typed refusal
    /// when absent). Unknown spellings cannot reach this function — S3
    /// already rejects them at config parse.
    ///
    /// # Errors
    /// [`CredentialInputError::NoCredentialsDirectory`] when the
    /// vocabulary names the systemd source and `directory` is `None`;
    /// [`CredentialInputError::EmptyCredentialsDirectory`] when it is
    /// `Some` but empty.
    pub fn resolve_in(
        vocabulary: ConfiguredCredentialSource,
        account: &AccountSection,
        directory: Option<&Path>,
        provider: InteractiveProvider<S>,
    ) -> Result<Self, CredentialInputError> {
        match vocabulary {
            ConfiguredCredentialSource::Interactive => Ok(Self::Interactive { provider }),
            ConfiguredCredentialSource::Systemd => {
                let directory = resolve_systemd_directory(directory)?;
                Ok(Self::Systemd(SystemdCredentialDirectory::new(
                    directory,
                    account.systemd_credential_names.clone(),
                )))
            }
        }
    }

    /// Reads one credential by short name through the active source.
    ///
    /// The interactive arm refuses blank values: a provider yielding
    /// `Some("")` gets the [`CredentialInputError::ProvidedEmpty`]
    /// refusal, symmetric with the systemd arm's empty-file refusal —
    /// a blank is never a credential on either arm.
    ///
    /// # Errors
    /// The active arm's typed refusals — see [`CredentialInputError`].
    pub fn read(&self, short_name: &str) -> Result<S, CredentialInputError> {
        match self {
            Self::Interactive { provider } => {
                let secret =
                    provider(short_name).ok_or_else(|| CredentialInputError::NotProvided {
                        name: short_name.to_owned(),
                    })?;
                // Fail-closed symmetry with the systemd arm's `Empty`
                // refusal. The second deliberate expose() consumer site
                // (see the module docs) — a blankness check, nothing
                // else may branch on the value here.
                if secret.expose().is_empty() {
                    return Err(CredentialInputError::ProvidedEmpty {
                        name: short_name.to_owned(),
                    });
                }
                Ok(secret)
            }
            Self::Systemd(directory) => directory.read(short_name),
        }
    }

    /// Reads the `session` credential and hands it to the deliberate
    /// consumer: parsed as the versioned FR-7C session envelope. The
    /// eventual caller is the S4 MuonAuth adapter's persistence facade
    /// (S5b wires it; this unit provides the seam only).
    ///
    /// # Errors
    /// The read's typed refusals, or [`CredentialInputError::Envelope`]
    /// when the value is not a current, integral envelope.
    pub fn read_session_envelope(&self) -> Result<SessionEnvelope, CredentialInputError> {
        let secret = self.read(SESSION_SHORT_NAME)?;
        parse_session_envelope(&secret)
    }
}

/// The FR-7C envelope bridge: the deliberate consumer of the `session`
/// credential, and the ONE `expose()` site in this crate. Mirrors the
/// fail-closed parse of `SessionEnvelopeStore::load` (unknown fields via
/// serde, unsupported schema, digest integrity) — the input side already
/// caps the value at [`MAX_CREDENTIAL_BYTES`], the same 64 KiB the
/// store side enforces. (The duplication is deliberate: `session.rs`
/// parses from a file path, and lifting a shared bytes-parser is S5b's
/// to make in its own file.)
///
/// # Errors
/// [`CredentialInputError::Envelope`] wrapping the store's typed
/// refusals — never a best-effort envelope. The `Parse` refusal is
/// reduced to serde's error CATEGORY plus line/column (see the private
/// `parse_error_summary` helper): serde's Display embeds the offending
/// value verbatim, and this module never carries value bytes.
pub fn parse_session_envelope<S: SecretBoundary>(
    secret: &S,
) -> Result<SessionEnvelope, CredentialInputError> {
    // The deliberate consumer: the one expose() site in this crate.
    let envelope: SessionEnvelope = serde_json::from_str(secret.expose()).map_err(|e| {
        CredentialInputError::Envelope(SessionEnvelopeError::Parse(parse_error_summary(&e)))
    })?;
    if envelope.schema_version != SESSION_SCHEMA_VERSION {
        return Err(CredentialInputError::Envelope(
            SessionEnvelopeError::UnsupportedSchema(envelope.schema_version),
        ));
    }
    if !envelope.verify_integrity() {
        return Err(CredentialInputError::Envelope(
            SessionEnvelopeError::Integrity,
        ));
    }
    Ok(envelope)
}

/// The systemd arm's directory resolution, shared by the env-backed and
/// injected entry points: absent fails as [`CredentialInputError::
/// NoCredentialsDirectory`] (FR-7J) and a set-but-empty value fails as
/// [`CredentialInputError::EmptyCredentialsDirectory`] — an empty path
/// would otherwise resolve credential names against the process working
/// directory and misreport every read as a bare relative `Missing`.
fn resolve_systemd_directory(directory: Option<&Path>) -> Result<PathBuf, CredentialInputError> {
    let directory = directory.ok_or(CredentialInputError::NoCredentialsDirectory)?;
    if directory.as_os_str().is_empty() {
        return Err(CredentialInputError::EmptyCredentialsDirectory);
    }
    Ok(directory.to_path_buf())
}

/// serde's error Display embeds the offending VALUE verbatim (an
/// `invalid type: string "…"` refusal carries the misprovisioned bytes —
/// for a session slot, that is a password riding daemon error logs).
/// The parse refusal is therefore reduced to its value-free facts: the
/// `classify()` category (kind, never the message) plus line/column.
pub(crate) fn parse_error_summary(error: &serde_json::Error) -> String {
    let kind = match error.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "eof",
    };
    format!(
        "{} error at line {} column {}",
        kind,
        error.line(),
        error.column()
    )
}

/// A credential name must be exactly one plain file name: non-empty, no
/// path separators (which would escape the trust root — SEC-16B), no
/// NUL, and not `.`/`..`.
fn is_plain_file_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(['/', '\0']) && name != "." && name != ".."
}

/// Every way a credential read can refuse. Payloads name the credential
/// and its path; they never carry value bytes.
#[derive(Debug, thiserror::Error)]
pub enum CredentialInputError {
    /// The systemd source was configured but `$CREDENTIALS_DIRECTORY` is
    /// not set (not running under systemd with credentials provisioned).
    #[error(
        "the systemd credential source requires the CREDENTIALS_DIRECTORY \
         environment variable (set by systemd LoadCredential=; absent when \
         not provisioned)"
    )]
    NoCredentialsDirectory,
    /// `$CREDENTIALS_DIRECTORY` is set but empty. Distinct from absent:
    /// systemd always provisions an absolute per-unit path, so an empty
    /// value is a broken deployment — left unchecked it would resolve
    /// credential names against the process working directory and
    /// misreport every read as a bare relative `Missing`.
    #[error(
        "the CREDENTIALS_DIRECTORY environment variable is set but empty \
         (systemd always provisions an absolute per-unit path)"
    )]
    EmptyCredentialsDirectory,
    /// The short name has no entry in `account.systemd_credential_names`.
    #[error(
        "no systemd credential name configured for `{name}` \
         (account.systemd_credential_names)"
    )]
    NameNotConfigured {
        /// The requested short name.
        name: String,
    },
    /// The configured credential name is not a plain file name inside
    /// the credentials directory (SEC-16B: no path traversal).
    #[error(
        "credential name `{name}` is not a plain file name under the \
         credentials directory (SEC-16B: no path traversal)"
    )]
    BadCredentialName {
        /// The offending configured credential name.
        name: String,
    },
    /// The credential file does not exist.
    #[error("credential `{name}` is missing at {path}")]
    Missing {
        /// The credential name.
        name: String,
        /// The absent file.
        path: PathBuf,
    },
    /// The credential file could not be opened or read.
    #[error("credential `{name}` at {path} could not be read: {source}")]
    Unreadable {
        /// The credential name.
        name: String,
        /// The unreadable file.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },
    /// The credential value is empty — never a blank credential.
    #[error("credential `{name}` at {path} is empty")]
    Empty {
        /// The credential name.
        name: String,
        /// The empty file.
        path: PathBuf,
    },
    /// The credential value exceeds the size cap (SEC-16B size-bounded
    /// reads; the cap matches the session-envelope ceiling).
    #[error("credential `{name}` at {path} is {size} bytes, over the {cap}-byte cap")]
    Oversized {
        /// The credential name.
        name: String,
        /// The oversized file.
        path: PathBuf,
        /// The file's size in bytes.
        size: u64,
        /// The ceiling that was exceeded ([`MAX_CREDENTIAL_BYTES`]).
        cap: usize,
    },
    /// The credential bytes are not valid UTF-8. The invalid sequence is
    /// deliberately NOT included in the error (it is credential bytes).
    #[error("credential `{name}` at {path} is not valid UTF-8")]
    NotUtf8 {
        /// The credential name.
        name: String,
        /// The file that is not UTF-8.
        path: PathBuf,
    },
    /// The credential leaf grants group or world permission bits;
    /// systemd provisions credentials owner-only (`0400` in a `0700`
    /// directory), so group/world READ on a credential file is
    /// disclosure, not just tampering surface.
    #[error(
        "credential `{name}` at {path} has mode {mode:#o} granting \
         group/world access; systemd credentials are owner-only"
    )]
    ExcessivePermission {
        /// The credential name.
        name: String,
        /// The offending file.
        path: PathBuf,
        /// Its permission bits (masked to 0o777).
        mode: u32,
    },
    /// The interactive surface provided no value for the name.
    #[error("the interactive credential surface provided no value for `{name}`")]
    NotProvided {
        /// The requested short name.
        name: String,
    },
    /// The interactive surface provided an EMPTY value — never a blank
    /// credential. The interactive twin of the systemd arm's
    /// [`CredentialInputError::Empty`] refusal: a misbehaving S9 client
    /// handing back an empty string is treated exactly like an empty
    /// credential file (fail-closed symmetry — qa round decision).
    #[error(
        "the interactive credential surface provided an empty value for `{name}` \
         (a blank is not a credential)"
    )]
    ProvidedEmpty {
        /// The requested short name.
        name: String,
    },
    /// The credentials tree failed the fs_trust walk (symlink,
    /// wrong type, group/world write, or non-root ownership) — the
    /// directory is not the systemd-provisioned tree it must be.
    #[error("untrusted credentials tree: {0}")]
    Untrusted(#[from] FsTrustError),
    /// The session credential is not a current, integral envelope.
    #[error("session credential is not a valid envelope: {0}")]
    Envelope(#[from] SessionEnvelopeError),
}

/// The peer-secret test double and its counters, shared by every test
/// module below. Counters are thread-local: `ingress`/`expose` are
/// static trait functions with no context parameter, libtest runs tests
/// in parallel, and per-thread deltas keep the exactly-once assertions
/// race-free without `unsafe` env or process-global state.
#[cfg(test)]
mod test_support {
    use super::SecretBoundary;
    use std::cell::Cell;

    thread_local! {
        static INGRESS_CALLS: Cell<usize> = const { Cell::new(0) };
        static EXPOSE_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    /// Mirrors `PeerSecret`'s contract: zeroizing storage is the
    /// production side of the boundary; here what matters is that every
    /// value crosses `ingress` and is read back only via `expose`, and
    /// that Debug never renders the value.
    #[derive(Clone)]
    pub(super) struct TestSecret(String);

    impl SecretBoundary for TestSecret {
        fn ingress(value: String) -> Self {
            INGRESS_CALLS.with(|calls| calls.set(calls.get() + 1));
            Self(value)
        }
        fn expose(&self) -> &str {
            EXPOSE_CALLS.with(|calls| calls.set(calls.get() + 1));
            &self.0
        }
    }
    impl std::fmt::Debug for TestSecret {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("[redacted-test]")
        }
    }

    /// Ingress calls made on this test's thread so far.
    pub(super) fn ingresses() -> usize {
        INGRESS_CALLS.with(Cell::get)
    }
    /// Expose calls made on this test's thread so far.
    pub(super) fn exposes() -> usize {
        EXPOSE_CALLS.with(Cell::get)
    }

    /// The zero-ingress pin on every systemd refusal arm: no value may
    /// cross the source boundary when the read refuses. Kills the
    /// mutation class qa's round survived ("ingress moved to
    /// immediately-after-read, before all gates" passed the pre-fix
    /// suite 24/24 because no refusal arm asserted the boundary count);
    /// the success arm's exactly-once pin lives in
    /// `provisioned_credential_crosses_exactly_one_ingress_unchanged`.
    pub(super) fn assert_no_ingress<R>(body: impl FnOnce() -> R) -> R {
        let before = ingresses();
        let result = body();
        assert_eq!(
            ingresses(),
            before,
            "a refusal must not cross the ingress boundary — values enter \
             only after every gate passes"
        );
        result
    }
}

/// The systemd fail-closed matrix. Positive arms need a root-owned tree
/// (the walker's ownership pass) and follow the suite's established
/// runner-gated skip pattern; every negative arm is provable
/// unprivileged.
#[cfg(test)]
mod systemd_read_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use test_support::TestSecret;
    use test_support::assert_no_ingress;

    /// A systemd-shaped tree: 0700 credentials directory, one 0400 leaf
    /// per (credential-name, value), the default name mappings.
    fn credentials_tree(
        root: &Path,
        files: &[(&str, &str)],
    ) -> SystemdCredentialDirectory<TestSecret> {
        let dir = root.join("credentials");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (file_name, value) in files {
            let path = dir.join(file_name);
            std::fs::write(&path, value).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let mut names = BTreeMap::new();
        names.insert("session".to_owned(), "protonwire-session".to_owned());
        names.insert("username".to_owned(), "protonwire-username".to_owned());
        SystemdCredentialDirectory::new(&dir, names)
    }

    /// The walker's ownership pass demands root:root; only a runner
    /// whose artifacts read as root-owned can construct the accept tree
    /// (the `strict_load_accepts_clean_root_owned_tree` pattern).
    fn tree_is_root_owned(source: &SystemdCredentialDirectory<TestSecret>) -> bool {
        std::fs::metadata(source.directory())
            .map(|meta| meta.uid() == 0 && meta.gid() == 0)
            .unwrap_or(false)
    }

    /// FR-7F positive arm: a provisioned credential is read fully,
    /// crosses the peer-secret ingress exactly once, renders redacted,
    /// and the file is untouched afterwards (read-only import — no
    /// write-back path exists in this unit at all).
    #[test]
    fn provisioned_credential_crosses_exactly_one_ingress_unchanged() {
        use test_support::{exposes, ingresses};
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(
            root.path(),
            &[("protonwire-session", "tok-provisioned-0001")],
        );
        if !tree_is_root_owned(&source) {
            return; // uid-0 ownership arm unprovable for this runner
        }
        let (before_ingress, before_expose) = (ingresses(), exposes());
        let secret = source.read("session").expect("a clean tree must read");
        assert_eq!(
            ingresses() - before_ingress,
            1,
            "the value must cross the boundary exactly once"
        );
        assert_eq!(exposes() - before_expose, 0, "read must not expose");
        assert_eq!(secret.expose(), "tok-provisioned-0001");
        assert_eq!(format!("{secret:?}"), "[redacted-test]");

        // Read-only import: same bytes, same owner-only mode, after read.
        let path = source.directory().join("protonwire-session");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "tok-provisioned-0001"
        );
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
    }

    /// Missing credential file: typed `Missing`, never a blank value.
    #[test]
    fn missing_credential_file_is_a_typed_missing_error() {
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(root.path(), &[]);
        let err = assert_no_ingress(|| source.read("session")).unwrap_err();
        assert!(
            matches!(err, CredentialInputError::Missing { ref name, ref path }
                if name == "protonwire-session" && path.ends_with("protonwire-session")),
            "must be Missing naming the file: {err}"
        );
    }

    /// Empty value: refused, never a blank credential.
    #[test]
    fn empty_credential_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(root.path(), &[("protonwire-session", "")]);
        assert!(matches!(
            assert_no_ingress(|| source.read("session")),
            Err(CredentialInputError::Empty { .. })
        ));
    }

    /// SEC-16B size-bounded reads: a value over the cap is refused
    /// without being read whole; exactly-at-cap is not over it.
    #[test]
    fn oversized_credential_is_refused() {
        use test_support::ingresses;
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(root.path(), &[("protonwire-session", "x")]);
        let path = source.directory().join("protonwire-session");
        // The fixture is 0400 (owner has no write bit); reopen for the
        // test's own staged content.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, vec![b'x'; MAX_CREDENTIAL_BYTES + 1]).unwrap();
        match assert_no_ingress(|| source.read("session")) {
            Err(CredentialInputError::Oversized { size, cap, .. }) => {
                assert_eq!(cap, MAX_CREDENTIAL_BYTES);
                assert_eq!(size, MAX_CREDENTIAL_BYTES as u64 + 1);
            }
            other => panic!("expected Oversized, got {other:?}"),
        }
        // Boundary: exactly at the cap is not over it (on unprivileged
        // runners the trust walk's ownership arm refuses instead —
        // either way, not Oversized). Both runner shapes keep the
        // boundary count honest: a refusal crosses nothing, a success
        // crosses exactly once.
        std::fs::write(&path, vec![b'x'; MAX_CREDENTIAL_BYTES]).unwrap();
        let before = ingresses();
        match source.read("session") {
            Ok(secret) => {
                assert_eq!(secret.expose().len(), MAX_CREDENTIAL_BYTES);
                assert_eq!(ingresses() - before, 1, "success crosses exactly once");
            }
            Err(CredentialInputError::Oversized { .. }) => {
                panic!("at-cap must not be Oversized")
            }
            Err(_) => assert_eq!(ingresses() - before, 0, "a refusal crosses nothing"),
        }
    }

    /// Credentials are text (envelopes are JSON; usernames and passwords
    /// are strings): non-UTF-8 bytes are refused, and the error carries
    /// no value bytes (`FromUtf8Error`'s Display embeds the sequence).
    #[test]
    fn non_utf8_credential_is_refused_without_leaking_bytes() {
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(root.path(), &[("protonwire-session", "x")]);
        let path = source.directory().join("protonwire-session");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, [0x80u8, 0xff, 0xfe, 0x7f]).unwrap();
        match assert_no_ingress(|| source.read("session")) {
            Err(err @ CredentialInputError::NotUtf8 { .. }) => {
                assert!(!err.to_string().contains("0x"), "no bytes in: {err}");
            }
            other => panic!("expected NotUtf8, got {other:?}"),
        }
    }

    /// systemd provisions credentials owner-only; a group/world-readable
    /// leaf is disclosure and is refused even though the fs_trust walker
    /// itself only rejects write bits.
    #[test]
    fn world_readable_credential_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(root.path(), &[("protonwire-session", "tok-1")]);
        let path = source.directory().join("protonwire-session");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        match assert_no_ingress(|| source.read("session")) {
            Err(CredentialInputError::ExcessivePermission { mode, .. }) => {
                assert_eq!(mode, 0o644)
            }
            other => panic!("expected ExcessivePermission, got {other:?}"),
        }
    }

    /// SEC-16B / fd-pinning semantics: a symlinked credential is
    /// refused AT OPEN (`O_NOFOLLOW` → `ELOOP` → the typed symlink
    /// refusal) even when its target is perfectly clean — the link
    /// itself is the defect; its target is never consulted, so there is
    /// no follow to race. Before S5b this refusal came from a separate
    /// `lstat` pass ahead of the open; the outcome is pinned unchanged.
    #[test]
    fn symlinked_credential_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(root.path(), &[]);
        let dir = source.directory();
        let real = root.path().join("real-secret");
        std::fs::write(&real, "tok-laundered").unwrap();
        std::os::unix::fs::symlink(&real, dir.join("protonwire-session")).unwrap();
        let err = assert_no_ingress(|| source.read("session")).unwrap_err();
        assert!(
            matches!(
                err,
                CredentialInputError::Untrusted(FsTrustError::Symlink { .. })
            ),
            "must be the symlink defect: {err}"
        );
    }

    /// An entry that is a subdirectory where a credential file should be
    /// is refused (the walker's regular-file rule).
    #[test]
    fn subdirectory_credential_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(root.path(), &[]);
        std::fs::create_dir(source.directory().join("protonwire-session")).unwrap();
        let err = assert_no_ingress(|| source.read("session")).unwrap_err();
        assert!(
            matches!(
                err,
                CredentialInputError::Untrusted(FsTrustError::NotARegularFile { .. })
            ),
            "must be the wrong-type defect: {err}"
        );
    }

    /// SEC-16B: credential names are plain file names — every
    /// traversal-shaped name is refused BEFORE any filesystem access,
    /// even when the escaped-to file really exists.
    #[test]
    fn traversal_shaped_credential_names_are_refused() {
        let root = tempfile::tempdir().unwrap();
        // The file a traversal would reach, planted to prove the refusal
        // is by name, not by accident of absence.
        std::fs::write(root.path().join("escape"), "tok-escaped").unwrap();
        let dir = root.path().join("credentials");
        std::fs::create_dir_all(&dir).unwrap();
        for bad in ["../escape", "sub/creds", "/etc/passwd", ".", "..", ""] {
            let mut names = BTreeMap::new();
            names.insert("session".to_owned(), bad.to_owned());
            let source = SystemdCredentialDirectory::<TestSecret>::new(&dir, names);
            match assert_no_ingress(|| source.read("session")) {
                Err(CredentialInputError::BadCredentialName { name }) => assert_eq!(name, bad),
                other => panic!("`{bad}` must be BadCredentialName, got {other:?}"),
            }
        }
    }

    /// The trust root is the credentials directory itself, and the
    /// walker walks it: a group-writable credentials directory lets any
    /// local user plant credentials, so the directory is refused.
    #[test]
    fn group_writable_credentials_directory_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(root.path(), &[("protonwire-session", "tok-1")]);
        std::fs::set_permissions(source.directory(), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        let err = assert_no_ingress(|| source.read("session")).unwrap_err();
        assert!(
            matches!(
                err,
                CredentialInputError::Untrusted(FsTrustError::GroupWorldWritable { .. })
            ),
            "must be the directory's mode defect: {err}"
        );
    }

    /// The ownership arm: a tree that is not the systemd-provisioned
    /// root-owned tree is refused. Unprivileged runners construct it for
    /// free (their artifacts are non-root-owned); root runners hand the
    /// tree to uid/gid 65534.
    #[test]
    fn non_root_owned_tree_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(root.path(), &[("protonwire-session", "tok-1")]);
        let dir = source.directory();
        if std::fs::metadata(dir).unwrap().uid() == 0 {
            let _ = std::os::unix::fs::chown(dir, Some(65534), Some(65534));
        }
        if std::fs::metadata(dir).unwrap().uid() == 0 {
            return; // cannot construct a non-root-owned tree here
        }
        let err = assert_no_ingress(|| source.read("session")).unwrap_err();
        assert!(
            matches!(
                err,
                CredentialInputError::Untrusted(FsTrustError::NotRootOwned { .. })
            ),
            "must be the ownership defect: {err}"
        );
    }

    /// A short name with no configured mapping is refused — the
    /// administrator names every consumable credential.
    #[test]
    fn unconfigured_short_name_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(root.path(), &[]);
        match assert_no_ingress(|| source.read("totp")) {
            Err(CredentialInputError::NameNotConfigured { name }) => assert_eq!(name, "totp"),
            other => panic!("expected NameNotConfigured, got {other:?}"),
        }
    }

    /// S5a sec P3 (fd-pinning), order pin: the owner-only MODE gate runs
    /// on the fstat of the PINNED descriptor, BEFORE any byte is read —
    /// the disclosure-class defect beats content-class defects even when
    /// both are present. RED (observed first): the pre-fix tree checked
    /// content before mode, so this empty-and-world-readable leaf was
    /// refused as `Empty`.
    #[test]
    fn a_world_readable_leaf_refuses_on_mode_before_content_gates() {
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(root.path(), &[("protonwire-session", "")]);
        let path = source.directory().join("protonwire-session");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        match assert_no_ingress(|| source.read("session")) {
            Err(CredentialInputError::ExcessivePermission { mode, .. }) => assert_eq!(mode, 0o644),
            other => panic!("expected ExcessivePermission before the empty check, got {other:?}"),
        }
    }

    /// Same order pin against the size gate: the fstat SIZE is checked
    /// before the read, so an oversized-and-world-readable leaf refuses
    /// on mode too. RED (observed first): pre-fix the content read ran
    /// first and this was refused as `Oversized`.
    #[test]
    fn a_world_readable_leaf_refuses_on_mode_before_the_size_gate() {
        let root = tempfile::tempdir().unwrap();
        let source = credentials_tree(root.path(), &[("protonwire-session", "x")]);
        let path = source.directory().join("protonwire-session");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        std::fs::write(&path, vec![b'x'; MAX_CREDENTIAL_BYTES + 1]).unwrap();
        match assert_no_ingress(|| source.read("session")) {
            Err(CredentialInputError::ExcessivePermission { mode, .. }) => assert_eq!(mode, 0o664),
            other => panic!("expected ExcessivePermission before the size check, got {other:?}"),
        }
    }

    /// Sec obligation A (S5a sec P2), the storage-type pin: the read
    /// path's value transit is zeroizing from the first byte to the
    /// ingress seam, and the seam MOVES the allocation out of transit
    /// (`mem::take`) rather than copying it. Class: compile-red —
    /// observed pre-fix as `read_bounded`/`open_pinned` absent (the
    /// path held plain `Vec<u8>`/`String`); the drop-zeroizes behavior
    /// itself is the `zeroize` crate's own, upstream-tested, and is not
    /// observable from this workspace's `unsafe_code = deny` tests.
    #[test]
    fn value_transit_is_zeroizing_until_the_ingress_seam() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("credential");
        std::fs::write(&path, "tok-transit").unwrap();
        let file = open_pinned(&path).expect("a plain file opens pinned");
        let mut bytes: zeroize::Zeroizing<Vec<u8>> =
            read_bounded(&file, MAX_CREDENTIAL_BYTES).unwrap();
        let moved = String::from_utf8(std::mem::take(&mut *bytes)).expect("fixture is UTF-8");
        assert_eq!(moved, "tok-transit");
    }
}

/// The interactive seam (S9's surface, modeled as an injected provider
/// closure — no prompts exist in this unit).
#[cfg(test)]
mod interactive_tests {
    use super::*;
    use test_support::TestSecret;

    #[test]
    fn provider_values_flow_through_unchanged() {
        let provider: InteractiveProvider<TestSecret> = Arc::new(|name| {
            (name == "session").then(|| TestSecret::ingress("from-s9-ipc".to_owned()))
        });
        let source = CredentialSource::Interactive { provider };
        let secret = source
            .read("session")
            .expect("the provider yielded a value");
        assert_eq!(secret.expose(), "from-s9-ipc");
        assert_eq!(format!("{secret:?}"), "[redacted-test]");
    }

    #[test]
    fn a_provider_without_a_value_is_a_typed_refusal() {
        let provider: InteractiveProvider<TestSecret> = Arc::new(|_| None);
        let source = CredentialSource::Interactive { provider };
        match source.read("session") {
            Err(CredentialInputError::NotProvided { name }) => assert_eq!(name, "session"),
            other => panic!("expected NotProvided, got {other:?}"),
        }
    }

    /// qa gap (decision: REFUSE — fail-closed symmetry with the systemd
    /// arm's `Empty`): the interactive arm used to accept `Some("")` as
    /// a blank credential while the systemd arm refused empty files.
    /// Red observed first in the behavioral is_err form against the
    /// pre-fix tree: `Ok([redacted-test])`.
    #[test]
    fn a_provider_handing_back_an_empty_value_is_a_typed_refusal() {
        let provider: InteractiveProvider<TestSecret> =
            Arc::new(|_| Some(TestSecret::ingress(String::new())));
        let source = CredentialSource::Interactive { provider };
        match source.read("session") {
            Err(CredentialInputError::ProvidedEmpty { name }) => assert_eq!(name, "session"),
            other => panic!("expected ProvidedEmpty, got {other:?}"),
        }
    }
}

/// S3 vocabulary -> source resolution (total; unknown spellings already
/// fail at config parse — the sections suite pins that).
#[cfg(test)]
mod resolution_tests {
    use super::*;
    use test_support::TestSecret;

    fn account() -> AccountSection {
        AccountSection::default()
    }

    fn any_provider() -> InteractiveProvider<TestSecret> {
        Arc::new(|_| None)
    }

    #[test]
    fn interactive_vocabulary_resolves_to_the_provider_arm() {
        let resolved = CredentialSource::resolve_in(
            ConfiguredCredentialSource::Interactive,
            &account(),
            None, // a directory would be a misconfiguration for this arm
            any_provider(),
        )
        .expect("interactive needs no directory");
        assert!(matches!(resolved, CredentialSource::Interactive { .. }));
    }

    #[test]
    fn systemd_vocabulary_resolves_to_the_directory_arm() {
        let root = tempfile::tempdir().unwrap();
        let resolved = CredentialSource::<TestSecret>::resolve_in(
            ConfiguredCredentialSource::Systemd,
            &account(),
            Some(root.path()),
            any_provider(),
        )
        .expect("a present directory resolves");
        match resolved {
            CredentialSource::Systemd(directory) => {
                assert_eq!(directory.directory(), root.path());
            }
            other => panic!("expected the Systemd arm, got {other:?}"),
        }
    }

    /// qa gap: a SET-but-empty `$CREDENTIALS_DIRECTORY` used to resolve
    /// to a bare relative path, misreporting every subsequent read as
    /// `Missing { name, path: "protonwire-session" }` — the wrong error
    /// class for a broken deployment. Pins BOTH directions: absent is
    /// the FR-7J `NoCredentialsDirectory` refusal, empty is its own
    /// distinct defect (red observed first in the behavioral is_err
    /// form against the pre-fix tree: `Ok(Systemd)`).
    #[test]
    fn empty_and_absent_credentials_directory_are_distinct_refusals() {
        let empty = CredentialSource::<TestSecret>::resolve_in(
            ConfiguredCredentialSource::Systemd,
            &account(),
            Some(Path::new("")),
            any_provider(),
        )
        .unwrap_err();
        assert!(
            matches!(empty, CredentialInputError::EmptyCredentialsDirectory),
            "a set-but-empty directory must be EmptyCredentialsDirectory: {empty}"
        );
        assert!(
            empty.to_string().contains("empty"),
            "the message must name the defect: {empty}"
        );
        let absent = CredentialSource::<TestSecret>::resolve_in(
            ConfiguredCredentialSource::Systemd,
            &account(),
            None,
            any_provider(),
        )
        .unwrap_err();
        assert!(
            matches!(absent, CredentialInputError::NoCredentialsDirectory),
            "absent stays the FR-7J refusal: {absent}"
        );
        assert_ne!(
            empty.to_string(),
            absent.to_string(),
            "the two directions are distinct classes, not one message"
        );
    }

    /// FR-7J: a configured source that is unavailable fails closed.
    #[test]
    fn systemd_vocabulary_without_a_directory_fails_closed() {
        let err = CredentialSource::<TestSecret>::resolve_in(
            ConfiguredCredentialSource::Systemd,
            &account(),
            None,
            any_provider(),
        )
        .unwrap_err();
        assert!(
            matches!(err, CredentialInputError::NoCredentialsDirectory),
            "must be NoCredentialsDirectory: {err}"
        );
        assert!(
            err.to_string().contains("CREDENTIALS_DIRECTORY"),
            "the message must name the variable: {err}"
        );
    }

    /// The production entry point is env-backed: its outcome matches the
    /// live `$CREDENTIALS_DIRECTORY` (read-only assertion — edition 2024
    /// forbids the test from staging the variable).
    #[test]
    fn resolve_reads_the_live_environment() {
        let outcome = CredentialSource::<TestSecret>::resolve(
            ConfiguredCredentialSource::Systemd,
            &account(),
            any_provider(),
        );
        match std::env::var_os(CREDENTIALS_DIRECTORY_VAR) {
            None => assert!(matches!(
                outcome,
                Err(CredentialInputError::NoCredentialsDirectory)
            )),
            Some(value) if value.is_empty() => assert!(matches!(
                outcome,
                Err(CredentialInputError::EmptyCredentialsDirectory)
            )),
            Some(_) => assert!(outcome.is_ok()),
        }
    }
}

/// The FR-7C envelope bridge: the deliberate consumer and its only
/// `expose()` site. `parse_session_envelope` arms run without
/// filesystem access (hence unprivileged); the end-to-end read arm is
/// root-gated with the tree.
#[cfg(test)]
mod envelope_bridge_tests {
    use super::*;
    use serde_json::json;
    use test_support::TestSecret;
    use test_support::exposes;

    fn creds(token: &str) -> serde_json::Value {
        json!({
            "UID": "uid-1",
            "UserID": "user-1",
            "AccessToken": token,
            "RefreshToken": "refresh-1",
            "Scopes": ["loggedin", "full"],
        })
    }

    fn wrapped_envelope(envelope: &SessionEnvelope) -> TestSecret {
        TestSecret::ingress(serde_json::to_string(envelope).unwrap())
    }

    #[test]
    fn a_valid_envelope_parses_with_exactly_one_expose() {
        let envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        let secret = wrapped_envelope(&envelope);
        let before = exposes();
        let parsed = parse_session_envelope(&secret).expect("a valid envelope parses");
        assert_eq!(exposes() - before, 1, "expose happens exactly once, here");
        assert_eq!(parsed, envelope);
    }

    #[test]
    fn future_schema_versions_are_refused_fail_closed() {
        let envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        let future = json!({
            "schema_version": crate::session::SESSION_SCHEMA_VERSION + 1,
            "envelope_generation": 1,
            "source_digest": envelope.source_digest,
            "credentials": creds("acc-1"),
        });
        let secret = TestSecret::ingress(future.to_string());
        match parse_session_envelope(&secret) {
            Err(CredentialInputError::Envelope(SessionEnvelopeError::UnsupportedSchema(
                version,
            ))) => {
                assert_eq!(version, crate::session::SESSION_SCHEMA_VERSION + 1);
            }
            other => panic!("expected UnsupportedSchema, got {other:?}"),
        }
    }

    #[test]
    fn tampered_credentials_fail_integrity() {
        let mut envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        envelope.credentials = creds("attacker-swap");
        let secret = wrapped_envelope(&envelope);
        assert!(matches!(
            parse_session_envelope(&secret),
            Err(CredentialInputError::Envelope(
                SessionEnvelopeError::Integrity
            ))
        ));
    }

    #[test]
    fn garbage_is_refused() {
        let secret = TestSecret::ingress("{ not json".to_owned());
        assert!(matches!(
            parse_session_envelope(&secret),
            Err(CredentialInputError::Envelope(SessionEnvelopeError::Parse(
                _
            )))
        ));
    }

    /// Rust-review P1 (S5a FAIL item): serde's Display embeds the
    /// offending VALUE verbatim — a misprovisioned session slot holding a
    /// password where the envelope expects a number rides the refusal as
    /// `... invalid type: string "hunter2-super-secret-password",
    /// expected u32 ...`, falsifying this module's never-carry-the-value
    /// promise the moment it reaches daemon error logs. The probe embeds
    /// a distinctive wrong-typed value and asserts the refusal names the
    /// error KIND and its line/column position, never the bytes.
    #[test]
    fn parse_refusals_carry_kind_and_position_but_never_the_value() {
        let envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        let slot = json!({
            // A password where the schema expects a `u32`.
            "schema_version": "hunter2-super-secret-password",
            "envelope_generation": 1,
            "source_digest": envelope.source_digest,
            "credentials": creds("acc-1"),
        });
        let secret = TestSecret::ingress(slot.to_string());
        let err = parse_session_envelope(&secret)
            .expect_err("a wrong-typed schema_version must not parse");
        assert!(
            matches!(
                err,
                CredentialInputError::Envelope(SessionEnvelopeError::Parse(_))
            ),
            "must be the envelope Parse refusal: {err}"
        );
        let message = err.to_string();
        assert!(
            !message.contains("hunter2-super-secret-password"),
            "the refusal Display embeds the credential value: {message}"
        );
        assert!(
            message.contains("data") && message.contains("line") && message.contains("column"),
            "the refusal must name the error kind and its position: {message}"
        );
    }

    /// End-to-end (root-gated with the tree): the `session` credential
    /// reads AND parses through the deliberate-consumer seam.
    #[test]
    fn read_session_envelope_end_to_end() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("credentials");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        let path = dir.join("protonwire-session");
        std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();

        let mut names = BTreeMap::new();
        names.insert("session".to_owned(), "protonwire-session".to_owned());
        let source: CredentialSource<TestSecret> =
            CredentialSource::Systemd(SystemdCredentialDirectory::new(&dir, names));
        if std::fs::metadata(&dir).unwrap().uid() != 0 {
            return; // uid-0 ownership arm unprovable for this runner
        }
        let parsed = source
            .read_session_envelope()
            .expect("a clean tree with a valid envelope must parse");
        assert_eq!(parsed, envelope);
    }
}
