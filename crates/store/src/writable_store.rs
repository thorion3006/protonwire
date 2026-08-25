//! Writable session stores — the WRITABLE half of the credential
//! input/writable-store separation (M2 S5b; PRD FR-7E/FR-7EA/FR-7H,
//! SEC-3, m2-plan decision 2).
//!
//! [`resolve`] maps the S3 vocabulary `account.writable_session_store`
//! (`auto|keyring|tpm2|encrypted-local|none` — a closed vocabulary,
//! unknown spellings already fail at config parse) onto real stores:
//!
//! * [`ResolvedWritableStore::EncryptedLocal`] — the file-backed store
//!   under `/var/lib/protonwire` (the daemon's persistent-state trust
//!   domain, a DIFFERENT one from the systemd credentials directory the
//!   input half reads: that tree is PID 1's delivery boundary, this one
//!   is ours to manage). M2 ships the store as the mode-`0600`
//!   owner-only envelope file; the at-rest ENCRYPTION machinery is the
//!   post-M2 part of m2-plan decision 2 — the vocabulary spelling and
//!   the store identity land now so nothing shipped has to migrate
//!   later.
//! * [`ResolvedWritableStore::Memory`] — `none` (FR-7EA): the explicit
//!   no-persistence store. An ephemeral in-memory envelope; restart
//!   persistence is unavailable by construction.
//! * [`ResolvedWritableStore::Keyring`] — the freedesktop Secret
//!   Service store (S5c, decided by the §S5c spike in
//!   `docs/spike-2026-08.md`: keyring-core over the pure-Rust zbus
//!   store). Its AVAILABILITY is injected as [`SecretServiceStatus`]
//!   because the answer is deployment-owned: the root daemon reaches a
//!   desktop keyring only through the registered credential agent
//!   (FR-7JA), so the daemon's wiring injects `Unavailable` until that
//!   protocol ships the brokered store; the credential agent — running
//!   as the account owner — injects the answer of its own live probe.
//!   `auto` prefers the keyring when the injected status is
//!   `Available` and records a typed skip otherwise; an explicit
//!   `keyring` under `Unavailable` is a typed fail-closed refusal —
//!   never a silent fallback (FR-7E: "an explicitly selected backend
//!   must fail instead of falling through").
//! * `tpm2` — POST-M2 (decision 2). Naming it EXPLICITLY is a typed
//!   fail-closed refusal ([`WritableStoreError::Deferred`]) carrying
//!   the variant and the deferred status.
//! * `auto` — walks `account.writable_store_priority` and resolves to
//!   the first IMPLEMENTED candidate, recording a typed skip reason for
//!   every candidate passed over (FR-7E: "may skip an unavailable
//!   keyring only with a recorded reason"). With an `Available` Secret
//!   Service that is the keyring; otherwise the walk falls through to
//!   `encrypted-local`, recording why. If NO candidate is implemented
//!   the resolution FAILS CLOSED with
//!   [`WritableStoreError::NoImplementedStore`] — the FR-7EA
//!   confirmation requirement (continue as `none`?) is the S9 caller's
//!   to mint from that refusal, not this layer's to assume.
//!
//! # Fail-closed load, fd-pinned like the input half
//!
//! [`EncryptedLocalStore::load`] follows the S5b credential-read
//! discipline exactly (S5a sec P2/P3): ONE pinned `open(2)` with
//! `O_NOFOLLOW` (a symlinked leaf fails at open — `ELOOP` — the typed
//! symlink refusal), `fstat` OF THAT DESCRIPTOR for the regular-file
//! and size gates, the bytes read from the descriptor into
//! [`Zeroizing`] transit, then the fs_trust ancestor walk with the
//! trust root at `/var/lib/protonwire` (leaf pinned by the fd; the
//! walk covers the directory chain). The strict parse (unknown fields
//! via serde, unsupported schema, digest integrity — mirroring
//! [`SessionEnvelopeStore::load`]) runs BEFORE the walk so the refusal
//! matrix is provable on non-root development runners; nothing leaves
//! `load` before the walk passes — a refusal discards the transit
//! bytes (the input half's documented order rationale).
//!
//! # Value transit
//!
//! A credential VALUE never leaves this module except inside the
//! peer-secret boundary ([`SecretBoundary::ingress`] — the same
//! injected seam the input half is generic over):
//! [`ResolvedWritableStore::load_credentials`] serializes the embedded
//! envelope credentials into zeroizing transit and MOVES them across
//! the seam (`mem::take`), exactly the input half's discipline in
//! reverse.
//!
//! # The Secret Service store (S5c)
//!
//! [`KeyringSessionStore`] holds the SAME FR-7C envelope the file
//! store persists — one entry named by the envelope semantics (the
//! single-account daemon's one session: service `protonwire`, user
//! `session`), with the strict parse and the
//! generation-monotonicity refusal applied to the Secret Service
//! bytes exactly as to file bytes. Binding to the live service is
//! LAZY: `resolve` answering `keyring` constructs nothing and connects
//! nothing, because the daemon resolves this vocabulary too and
//! FR-7JA forbids the root daemon from joining a user's desktop
//! D-Bus session — the one process the live arm is legal in is the
//! credential agent (the account owner); the suite binds the
//! keyring-core mock store instead, so no test needs or contacts a
//! D-Bus daemon. Error classification is typed and byte-free: the
//! upstream keyring error variants that embed raw secret bytes are
//! reduced to their kind at the boundary and upstream Display strings
//! are never rendered into a refusal.
//!
//! # Atomic save
//!
//! [`EncryptedLocalStore::save`] delegates to [`SessionEnvelopeStore`]:
//! sibling temp file created mode `0600` AT CREATION, fsync, rename —
//! plus the generation-monotonicity refusal (a stale writer cannot
//! silently overwrite fresher credentials; S4 rust P2).

use std::io;
use std::mem;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use keyring_core::CredentialStore;
use keyring_core::Error as KeyringError;
use zeroize::Zeroizing;

use crate::ConfigPaths;
use crate::config::AccountSection;
use crate::config::WritableSessionStore as ConfiguredWritableStore;
use crate::credential_input::SecretBoundary;
use crate::credential_input::open_pinned;
use crate::credential_input::parse_error_summary;
use crate::credential_input::read_bounded;
use crate::fs_trust::FsTrustError;
use crate::fs_trust::MissingLeaf;
use crate::fs_trust::verify_trusted_path;
use crate::session::MAX_SESSION_BYTES;
use crate::session::SESSION_SCHEMA_VERSION;
use crate::session::SessionEnvelope;
use crate::session::SessionEnvelopeError;
use crate::session::SessionEnvelopeStore;

/// The encrypted-local envelope file name, beside the daemon state file
/// under `/var/lib/protonwire` (ConfigPaths-derived ONLY — see
/// [`EncryptedLocalStore::from_paths`]).
const SESSION_FILE_NAME: &str = "session.json";

/// The Secret Service entry's service name: the one product namespace
/// every ProtonWire secret lives under.
const KEYRING_SERVICE: &str = "protonwire";

/// The Secret Service entry's user name: the daemon is single-account
/// (one active owner UID; cross-UID isolation is the deployment's), so
/// the pair (`protonwire`, `session`) IS the envelope identity — the
/// same single-record identity the file store gives
/// `/var/lib/protonwire/session.json`, and the future agent protocol's
/// allowlisted record kind.
const KEYRING_USER: &str = "session";

/// Whether the Secret Service backend is usable in the calling
/// process. INJECTED by the caller because the answer is
/// deployment-owned, not store-owned (FR-7JA): the root daemon reaches
/// a desktop keyring only through the registered credential agent, so
/// the daemon's wiring passes its agent-registration state
/// (unregistered is `Unavailable` — the daemon process itself never
/// opens a D-Bus session); the credential agent, running as the
/// account owner, passes the answer of its own live probe; tests
/// inject both arms. [`resolve`] itself never touches D-Bus — it
/// trusts the injected status and constructs the keyring store lazily
/// (see [`KeyringSessionStore`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretServiceStatus {
    /// The Secret Service is usable here (the caller probed it, or is
    /// the process that owns the session bus).
    Available,
    /// Not usable — headless daemon, locked keyring, or no registered
    /// credential agent.
    Unavailable,
}

/// Resolves the S3 `account.writable_session_store` vocabulary against
/// the configured priority list, the canonical paths, and the injected
/// Secret Service availability. Total over the vocabulary — every
/// spelling has exactly one outcome, pinned by
/// `resolution_tests::every_spelling_of_the_vocabulary_resolves_totally`.
///
/// # Errors
/// [`WritableStoreError::SecretServiceUnavailable`] when an explicit
/// `keyring` is requested under an unavailable service (fail-closed,
/// never a fallback — FR-7E); [`WritableStoreError::Deferred`] when
/// `tpm2` is requested (post-M2, decision 2);
/// [`WritableStoreError::NoImplementedStore`] when `auto` exhausts the
/// priority list without an implemented candidate (the FR-7EA
/// confirmation is the caller's to mint).
pub fn resolve(
    vocabulary: ConfiguredWritableStore,
    account: &AccountSection,
    paths: &ConfigPaths,
    secret_service: SecretServiceStatus,
) -> Result<WritableStoreResolution, WritableStoreError> {
    match vocabulary {
        ConfiguredWritableStore::None => Ok(WritableStoreResolution {
            store: ResolvedWritableStore::Memory(MemorySessionStore::default()),
            skipped: Vec::new(),
        }),
        ConfiguredWritableStore::EncryptedLocal => Ok(WritableStoreResolution {
            store: ResolvedWritableStore::EncryptedLocal(EncryptedLocalStore::from_paths(paths)),
            skipped: Vec::new(),
        }),
        ConfiguredWritableStore::Keyring => match secret_service {
            SecretServiceStatus::Available => Ok(WritableStoreResolution {
                store: ResolvedWritableStore::Keyring(KeyringSessionStore::new()),
                skipped: Vec::new(),
            }),
            // FR-7E: an explicitly selected backend FAILS when
            // unavailable — falling through to another store would
            // persist credentials somewhere the administrator did not
            // choose.
            SecretServiceStatus::Unavailable => Err(WritableStoreError::SecretServiceUnavailable),
        },
        ConfiguredWritableStore::Auto => {
            // FR-7E: walk the priority list; the first IMPLEMENTED store
            // wins and every candidate passed over is RECORDED.
            let mut skipped = Vec::new();
            for candidate in &account.writable_store_priority {
                match candidate {
                    ConfiguredWritableStore::EncryptedLocal => {
                        return Ok(WritableStoreResolution {
                            store: ResolvedWritableStore::EncryptedLocal(
                                EncryptedLocalStore::from_paths(paths),
                            ),
                            skipped,
                        });
                    }
                    ConfiguredWritableStore::Keyring => match secret_service {
                        // Lazy construction: answering `keyring` must
                        // not connect the session bus (the daemon
                        // resolves this walk too — FR-7JA).
                        SecretServiceStatus::Available => {
                            return Ok(WritableStoreResolution {
                                store: ResolvedWritableStore::Keyring(KeyringSessionStore::new()),
                                skipped,
                            });
                        }
                        SecretServiceStatus::Unavailable => skipped.push(SkippedStore {
                            store: *candidate,
                            reason: SkipReason::SecretServiceUnavailable,
                        }),
                    },
                    ConfiguredWritableStore::Tpm2 => skipped.push(SkippedStore {
                        store: *candidate,
                        reason: SkipReason::NotImplementedInM2,
                    }),
                    // Defensive totality: config validation rejects
                    // `auto`/`none` as priority entries at load; a
                    // hand-built section carrying one still resolves
                    // totally — recorded, never silently honored.
                    ConfiguredWritableStore::Auto | ConfiguredWritableStore::None => {
                        skipped.push(SkippedStore {
                            store: *candidate,
                            reason: SkipReason::NotAConcreteStore,
                        })
                    }
                }
            }
            Err(WritableStoreError::NoImplementedStore {
                candidates: account
                    .writable_store_priority
                    .iter()
                    .map(|store| store.as_str().to_owned())
                    .collect(),
            })
        }
        // FR-7E: `tpm2` is post-M2 (decision 2) and fails closed,
        // naming the variant — never a fallback.
        requested @ ConfiguredWritableStore::Tpm2 => {
            Err(WritableStoreError::Deferred { store: requested })
        }
    }
}

/// A live writable session store plus the skip reasons `auto` recorded
/// on its way there (FR-7E; empty for explicit spellings).
#[derive(Debug, Clone)]
pub struct WritableStoreResolution {
    /// The resolved store.
    pub store: ResolvedWritableStore,
    /// Every candidate `auto` passed over, with the typed reason.
    pub skipped: Vec<SkippedStore>,
}

/// A concrete writable session store. The uniform facade (`save`/
/// `load`/`load_credentials`) is what S9's account surface consumes.
#[derive(Debug, Clone)]
pub enum ResolvedWritableStore {
    /// `none` (FR-7EA): in-memory only, restart persistence
    /// unavailable by construction.
    Memory(MemorySessionStore),
    /// `encrypted-local`: the file-backed store under
    /// `/var/lib/protonwire`.
    EncryptedLocal(EncryptedLocalStore),
    /// `keyring`: the freedesktop Secret Service store (S5c) — legal in
    /// the credential agent's process; see [`KeyringSessionStore`].
    Keyring(KeyringSessionStore),
}

impl ResolvedWritableStore {
    /// Persists the envelope through the active store.
    ///
    /// # Errors
    /// The encrypted-local and keyring arms' typed refusals — see
    /// [`WritableStoreError`]. The memory arm cannot fail.
    pub fn save(&self, envelope: &SessionEnvelope) -> Result<(), WritableStoreError> {
        match self {
            Self::Memory(memory) => {
                memory.save(envelope);
                Ok(())
            }
            Self::EncryptedLocal(store) => store.save(envelope),
            Self::Keyring(store) => store.save(envelope),
        }
    }

    /// Loads the envelope; a store that never held one (or, for
    /// `none`, a fresh instance) is `None`.
    ///
    /// # Errors
    /// The encrypted-local and keyring arms' strict-load refusals —
    /// see [`WritableStoreError`].
    pub fn load(&self) -> Result<Option<SessionEnvelope>, WritableStoreError> {
        match self {
            Self::Memory(memory) => Ok(memory.load()),
            Self::EncryptedLocal(store) => store.load(),
            Self::Keyring(store) => store.load(),
        }
    }

    /// The guarded credential handoff: the embedded envelope
    /// credentials cross the peer-secret boundary — a credential VALUE
    /// leaves this module only inside the boundary type, moved across
    /// the seam from zeroizing transit.
    ///
    /// # Errors
    /// The active arm's typed refusals — see [`WritableStoreError`].
    pub fn load_credentials<S: SecretBoundary>(&self) -> Result<Option<S>, WritableStoreError> {
        match self {
            Self::Memory(memory) => Ok(memory.load_credentials()),
            Self::EncryptedLocal(store) => store.load_credentials(),
            Self::Keyring(store) => store.load_credentials(),
        }
    }
}

/// One `auto` skip: the candidate passed over and why (FR-7E's
/// "recorded reason").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedStore {
    /// The candidate store that was skipped.
    pub store: ConfiguredWritableStore,
    /// Why it was not resolved to.
    pub reason: SkipReason,
}

/// The typed skip reasons `auto` records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The store is not implemented in M2 — post-M2 per m2-plan
    /// decision 2 (TPM2).
    NotImplementedInM2,
    /// The Secret Service was not usable in this process — the
    /// injected [`SecretServiceStatus`] said no (headless daemon,
    /// locked keyring, or no registered credential agent). FR-7E's
    /// "recorded reason" for the unavailable-keyring skip.
    SecretServiceUnavailable,
    /// The priority entry named `auto`/`none`, which name resolution
    /// POLICY, not stores; config validation rejects these at load, so
    /// this arm exists to keep `resolve` total against hand-built
    /// sections.
    NotAConcreteStore,
}

impl SkipReason {
    /// The recorded reason's text (the FR-7E record).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotImplementedInM2 => "not implemented in M2 (post-M2 per m2-plan decision 2)",
            Self::SecretServiceUnavailable => {
                "secret service unavailable in this process (FR-7JA: the daemon reaches a \
                 desktop keyring only through the registered credential agent)"
            }
            Self::NotAConcreteStore => {
                "not a concrete store (config validation rejects `auto`/`none` priority entries)"
            }
        }
    }
}

/// `none` (FR-7EA): the explicit no-persistence store. The envelope
/// lives in memory for the process lifetime only — a fresh instance
/// starts empty, which is exactly what "restart persistence
/// unavailable" means. Clones share the envelope (one logical session).
#[derive(Debug, Clone, Default)]
pub struct MemorySessionStore {
    envelope: Arc<Mutex<Option<SessionEnvelope>>>,
}

impl MemorySessionStore {
    /// Holds the envelope in memory; cannot fail.
    pub fn save(&self, envelope: &SessionEnvelope) {
        *self.lock() = Some(envelope.clone());
    }

    /// The in-memory envelope, if this instance (or a clone of it) ever
    /// saved one.
    #[must_use]
    pub fn load(&self) -> Option<SessionEnvelope> {
        self.lock().clone()
    }

    /// The guarded credential handoff for the in-memory envelope.
    #[must_use]
    pub fn load_credentials<S: SecretBoundary>(&self) -> Option<S> {
        // A parsed (or test-built) `Value` is always serializable — the
        // JSON grammar round-trips through `serde_json::Value`.
        self.load().map(|envelope| {
            credentials_through_boundary(envelope.credentials())
                .expect("a `serde_json::Value` is always serializable to a JSON string")
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<SessionEnvelope>> {
        // Poison recovery: a panic mid-save can only have skipped the
        // assignment or cloned an envelope — the `Option` invariant is
        // intact, so the guard is recovered, not propagated.
        self.envelope
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The `encrypted-local` writable session store: the FR-7C envelope
/// file under `/var/lib/protonwire`, beside the daemon state file.
///
/// Construction is ConfigPaths-derived ONLY ([`EncryptedLocalStore::from_paths`]) —
/// production gets `/var/lib/protonwire/session.json`, tests get
/// `ConfigPaths::rooted` — so there is exactly one way to address the
/// store and no caller can aim it at an arbitrary file.
#[derive(Debug, Clone)]
pub struct EncryptedLocalStore {
    inner: SessionEnvelopeStore,
    directory: PathBuf,
}

impl EncryptedLocalStore {
    /// Derives the store from the canonical paths: the session envelope
    /// lives beside the daemon state file, under
    /// `/var/lib/protonwire` in production (the strict load's trust
    /// root is that directory).
    #[must_use]
    pub fn from_paths(paths: &ConfigPaths) -> Self {
        // The `state.rs` idiom for a degenerate relative state_file
        // (neither constructor produces one): keep the derivation
        // literal and let the strict load's walk refuse it.
        let directory = paths
            .state_file
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();
        Self {
            inner: SessionEnvelopeStore::new(directory.join(SESSION_FILE_NAME)),
            directory,
        }
    }

    /// The envelope file path (`/var/lib/protonwire/session.json` in
    /// production).
    #[must_use]
    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    /// The trust root of the strict load (the daemon's persistent-state
    /// directory).
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The strict load: fd-pinned open, fstat gates, zeroizing read,
    /// strict parse, ancestor trust walk — see the module
    /// documentation. A missing file is `None`.
    ///
    /// # Errors
    /// [`WritableStoreError::Untrusted`] for the symlink/type/mode/
    /// ownership defects; [`WritableStoreError::Envelope`] for the
    /// size-cap, parse, schema, and integrity refusals and the I/O
    /// failures. Never a best-effort envelope.
    pub fn load(&self) -> Result<Option<SessionEnvelope>, WritableStoreError> {
        let path = self.inner.path();
        // 1. One pinned open: O_NOFOLLOW refuses a symlinked leaf AT
        //    OPEN (ELOOP -> the typed symlink refusal — the link is the
        //    defect, its target never consulted).
        let file = match open_pinned(path) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) if source.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32) => {
                return Err(WritableStoreError::Untrusted(FsTrustError::Symlink {
                    path: path.to_path_buf(),
                }));
            }
            Err(source) => {
                return Err(WritableStoreError::Envelope(SessionEnvelopeError::Io(
                    source,
                )));
            }
        };
        // 2. fstat THE DESCRIPTOR: regular-file type, then size
        //    (stat-first — a hostile file is refused before a single
        //    byte is read). Mode is the walker's own leaf pass below;
        //    this store WRITES 0600 and the walk rejects write bits.
        let meta = file
            .metadata()
            .map_err(SessionEnvelopeError::Io)
            .map_err(WritableStoreError::Envelope)?;
        if !meta.is_file() {
            return Err(WritableStoreError::Untrusted(
                FsTrustError::NotARegularFile {
                    path: path.to_path_buf(),
                },
            ));
        }
        if meta.len() > MAX_SESSION_BYTES as u64 {
            return Err(WritableStoreError::Envelope(SessionEnvelopeError::Parse(
                "session document exceeds size cap".into(),
            )));
        }
        // 3. Zeroizing read from the pinned descriptor (belt-and-braces
        //    post-read cap: the file may have grown since the fstat).
        let bytes = read_bounded(&file, MAX_SESSION_BYTES)
            .map_err(SessionEnvelopeError::Io)
            .map_err(WritableStoreError::Envelope)?;
        if bytes.len() > MAX_SESSION_BYTES {
            return Err(WritableStoreError::Envelope(SessionEnvelopeError::Parse(
                "session document exceeds size cap".into(),
            )));
        }
        // 4. Strict parse BEFORE the walk (unprivileged provability of
        //    the refusal matrix — the input half's documented order
        //    rationale): unknown fields via serde, unsupported schema,
        //    digest integrity.
        let envelope = parse_strict(&bytes)?;
        // 5. The authoritative ancestor walk, trust root at
        //    /var/lib/protonwire: the fd pins the LEAF; this walk
        //    covers its path and every ancestor to the root. Nothing
        //    has left this function — a refusal here discards the
        //    transit bytes.
        match verify_trusted_path(path, &self.directory, MissingLeaf::Reject) {
            Ok(()) => {}
            // Delete race after the pinned read: the bytes in hand came
            // from the pinned inode; the path is gone, so the next load
            // sees absence — report the same.
            Err(FsTrustError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        }
        Ok(Some(envelope))
    }

    /// The atomic save, delegated to [`SessionEnvelopeStore`]: sibling
    /// temp file mode `0600` AT CREATION, fsync, rename over the
    /// target, and the `envelope_generation` monotonicity refusal (a
    /// stale writer cannot silently overwrite fresher credentials).
    ///
    /// # Errors
    /// See [`WritableStoreError::Envelope`].
    pub fn save(&self, envelope: &SessionEnvelope) -> Result<(), WritableStoreError> {
        self.inner.save(envelope)?;
        Ok(())
    }

    /// The guarded credential handoff for the on-disk envelope.
    ///
    /// # Errors
    /// The strict load's refusals, or the envelope serialization
    /// refusal — see [`WritableStoreError`].
    pub fn load_credentials<S: SecretBoundary>(&self) -> Result<Option<S>, WritableStoreError> {
        let Some(envelope) = self.load()? else {
            return Ok(None);
        };
        Ok(Some(credentials_through_boundary(envelope.credentials())?))
    }
}

/// The bound Secret Service entry plus the store that backs it. The
/// store is kept alive beside the entry (the mock store's credentials
/// die with the store), and the entry is shared behind an `Arc` so
/// clones of the store are one logical session.
#[derive(Clone)]
struct BoundSecretService {
    #[allow(dead_code)] // kept alive deliberately; see the field comment
    store: Arc<CredentialStore>,
    entry: Arc<keyring_core::Entry>,
}

/// Where [`KeyringSessionStore`]'s entry comes from.
enum SecretServiceSource {
    /// The live zbus Secret Service (production). The FIRST store
    /// operation connects the session bus — the one process that is
    /// legal in is the credential agent running as the account owner
    /// (FR-7JA); see the type documentation on
    /// [`KeyringSessionStore`].
    Live,
    /// An explicit credential store: the keyring-core mock store in
    /// tests (no D-Bus daemon is needed or contacted anywhere in the
    /// suite), and the injection point a future brokered store uses.
    Explicit(Arc<CredentialStore>),
}

/// The `keyring` writable session store (S5c): the FR-7C versioned
/// envelope held by the freedesktop Secret Service, one entry named by
/// the envelope semantics — service `protonwire`, user `session` (the
/// single-account daemon's one session; the same identity the file
/// store gives `/var/lib/protonwire/session.json`). The envelope
/// discipline is unchanged from the file store: the strict parse
/// (`parse_strict`) and the generation-monotonicity refusal apply to
/// the Secret Service bytes exactly as to file bytes.
///
/// # Lazy bind — resolution never opens a D-Bus session
///
/// Binding to the live service happens at the FIRST store operation,
/// not at construction: [`resolve`] answering `keyring` must construct
/// nothing and connect nothing, because the daemon resolves this
/// vocabulary too and FR-7JA forbids the root daemon from joining a
/// user's desktop D-Bus session — the daemon's wiring injects
/// [`SecretServiceStatus::Unavailable`] until the S5c credential-agent
/// registration protocol ships the brokered store. A FAILED bind is
/// retried on the next operation (only a successful bind is cached):
/// a restarted session bus must not poison the process.
///
/// # Value transit
///
/// `get_secret` bytes move into [`Zeroizing`] transit on arrival and a
/// credential VALUE leaves this module only across the peer-secret
/// boundary (`load_credentials`). Residual, recorded in the S5c
/// spike: the Secret Service protocol decrypts the secret inside zbus
/// buffers this crate cannot zeroize — inherent to the dependency
/// (the file store's equivalent transit is fully zeroized).
///
/// `Debug` is manual and names only the entry identity: the upstream
/// entry type is deliberately opaque, and this store IS credentials
/// (the `SessionEnvelope` manual-`Debug` verdict applied to the store).
#[derive(Clone)]
pub struct KeyringSessionStore {
    /// Shared bind state (clones are one logical store, the memory
    /// store's discipline): `Ok` = bound and cached, `Err` = the last
    /// bind attempt's typed failure, `None` = not yet attempted.
    bind: Arc<Mutex<Option<Result<BoundSecretService, SecretServiceFailure>>>>,
    source: Arc<SecretServiceSource>,
}

impl std::fmt::Debug for KeyringSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyringSessionStore")
            .field("service", &KEYRING_SERVICE)
            .field("user", &KEYRING_USER)
            .field(
                "source",
                &match &*self.source {
                    SecretServiceSource::Live => "live",
                    SecretServiceSource::Explicit(_) => "explicit",
                },
            )
            .finish()
    }
}

impl Default for KeyringSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyringSessionStore {
    /// The production constructor: the live zbus Secret Service, bound
    /// lazily at first use. Legal in the credential agent's process —
    /// see the type documentation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bind: Arc::new(Mutex::new(None)),
            source: Arc::new(SecretServiceSource::Live),
        }
    }

    /// The injection seam: an explicit credential store. The test
    /// suite binds the keyring-core mock store here, so no test needs
    /// or contacts a D-Bus daemon.
    #[must_use]
    pub fn with_store(store: Arc<CredentialStore>) -> Self {
        Self {
            bind: Arc::new(Mutex::new(None)),
            source: Arc::new(SecretServiceSource::Explicit(store)),
        }
    }

    /// Binds the session entry, or returns the cached binding. A
    /// failed attempt is retried on the next call (see the type
    /// documentation); the lock is poison-recovered because the
    /// cached-state invariant survives any panic between check and
    /// write.
    fn bound(&self) -> Result<BoundSecretService, WritableStoreError> {
        let bind_failure = |failure: SecretServiceFailure| WritableStoreError::SecretService {
            operation: SecretServiceOperation::Bind,
            failure,
        };
        let mut guard = self
            .bind
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cached @ Ok(_)) = &*guard {
            return cached.clone().map_err(bind_failure);
        }
        let bound = Self::bind_now(&self.source);
        if let Ok(bound) = &bound {
            *guard = Some(Ok(bound.clone()));
        }
        bound.map_err(bind_failure)
    }

    /// One bind attempt against the configured source.
    fn bind_now(source: &SecretServiceSource) -> Result<BoundSecretService, SecretServiceFailure> {
        let store: Arc<CredentialStore> = match source {
            // Eager connect inside Store::new (the store's own design):
            // the first operation, never resolution, pays the D-Bus
            // round trip.
            SecretServiceSource::Live => zbus_secret_service_keyring_store::Store::new()
                .map_err(|error| classify_failure(&error))?,
            SecretServiceSource::Explicit(store) => Arc::clone(store),
        };
        let entry = store
            .build(KEYRING_SERVICE, KEYRING_USER, None)
            .map_err(|error| classify_failure(&error))?;
        Ok(BoundSecretService {
            store,
            entry: Arc::new(entry),
        })
    }

    /// Reads the raw entry bytes into zeroizing transit: `None` when
    /// no entry exists yet, the shared size-cap refusal for oversized
    /// blobs. (The Secret Service allocates the buffer before this
    /// crate can size-check it — the cap is post-allocation here,
    /// unlike the file store's stat-first gate; the service's own item
    /// limits bound the exposure. Recorded in the S5c spike.)
    fn read_bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>, WritableStoreError> {
        let bound = self.bound()?;
        let bytes = match bound.entry.get_secret() {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error @ KeyringError::NoEntry) => {
                drop(error);
                return Ok(None);
            }
            Err(error) => {
                return Err(WritableStoreError::SecretService {
                    operation: SecretServiceOperation::Load,
                    failure: classify_failure(&error),
                });
            }
        };
        if bytes.len() > MAX_SESSION_BYTES {
            return Err(WritableStoreError::Envelope(SessionEnvelopeError::Parse(
                "session document exceeds size cap".into(),
            )));
        }
        Ok(Some(bytes))
    }

    /// The strict load: the entry's bytes through the SAME refusal
    /// matrix as the file store (unknown fields, unsupported schema,
    /// digest integrity) — never a best-effort envelope.
    ///
    /// # Errors
    /// See [`WritableStoreError`].
    pub fn load(&self) -> Result<Option<SessionEnvelope>, WritableStoreError> {
        match self.read_bytes()? {
            None => Ok(None),
            Some(bytes) => parse_strict(&bytes).map(Some),
        }
    }

    /// Writes the envelope, with the file store's
    /// generation-monotonicity floor: a write whose
    /// `envelope_generation` is below the valid entry's is REFUSED
    /// before anything is written, and an unreadable existing entry
    /// fails the save rather than laundering a blind overwrite.
    ///
    /// # Errors
    /// See [`WritableStoreError`].
    pub fn save(&self, envelope: &SessionEnvelope) -> Result<(), WritableStoreError> {
        if let Some(on_service) = self.load()?
            && envelope.envelope_generation < on_service.envelope_generation
        {
            return Err(WritableStoreError::Envelope(
                SessionEnvelopeError::StaleGeneration {
                    attempted: envelope.envelope_generation,
                    on_disk: on_service.envelope_generation,
                },
            ));
        }
        let bytes = Zeroizing::new(serde_json::to_vec(envelope).map_err(|error| {
            WritableStoreError::Envelope(SessionEnvelopeError::Parse(parse_error_summary(&error)))
        })?);
        if bytes.len() > MAX_SESSION_BYTES {
            return Err(WritableStoreError::Envelope(SessionEnvelopeError::Parse(
                "session document exceeds size cap".into(),
            )));
        }
        let bound = self.bound()?;
        bound
            .entry
            .set_secret(&bytes)
            .map_err(|error| WritableStoreError::SecretService {
                operation: SecretServiceOperation::Save,
                failure: classify_failure(&error),
            })?;
        Ok(())
    }

    /// The guarded credential handoff for the Secret Service envelope.
    ///
    /// # Errors
    /// The strict load's refusals, or the envelope serialization
    /// refusal — see [`WritableStoreError`].
    pub fn load_credentials<S: SecretBoundary>(&self) -> Result<Option<S>, WritableStoreError> {
        let Some(envelope) = self.load()? else {
            return Ok(None);
        };
        Ok(Some(credentials_through_boundary(envelope.credentials())?))
    }
}

/// The Secret Service operation a typed failure is attributed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretServiceOperation {
    /// Binding the session entry to the live service.
    Bind,
    /// Reading the session entry.
    Load,
    /// Writing the session entry.
    Save,
}

impl SecretServiceOperation {
    /// The operation's name for the refusal record.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bind => "binding the session entry",
            Self::Load => "reading the session entry",
            Self::Save => "writing the session entry",
        }
    }
}

impl std::fmt::Display for SecretServiceOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The typed classification of a Secret Service refusal. Carries no
/// credential bytes by construction: the upstream keyring error
/// variants that embed raw secret bytes (`BadEncoding`,
/// `BadDataFormat`) are reduced to their kind here, and upstream
/// Display strings — which render those bytes — are never embedded
/// (this module's standing error discipline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretServiceFailure {
    /// The store could not be reached: no session bus, a locked
    /// collection, or a platform failure (upstream `NoStorageAccess`,
    /// `NoDefaultStore`, `PlatformFailure`).
    Unavailable,
    /// The stored secret is not decodable as this crate knows how to
    /// interpret it (upstream `BadEncoding`/`BadDataFormat`, and a
    /// `NoEntry` that escapes the callers that intercept it as
    /// absence); the raw bytes are discarded at this boundary, never
    /// rendered.
    Undecodable,
    /// Multiple entries match the session identity — ambiguous store
    /// state, refused rather than guessed (carries the count only).
    Ambiguous(usize),
    /// The store rejected the request as invalid, unsupported,
    /// malformed, or too long — carries the platform's detail string
    /// (parameter names and limits; never secret bytes).
    Rejected(String),
    /// A failure this classification does not know (the upstream error
    /// is `#[non_exhaustive]`). Deliberately carries no upstream text:
    /// an unvetted variant's Display is not safe to embed.
    Other,
}

impl std::fmt::Display for SecretServiceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => f.write_str(
                "the secret service is unreachable in this process (no session bus, a locked \
                 collection, or a platform failure)",
            ),
            Self::Undecodable => f.write_str(
                "the stored secret is not decodable (the raw bytes were discarded at the \
                 classification boundary, never rendered)",
            ),
            Self::Ambiguous(count) => write!(
                f,
                "{count} entries match the session identity — ambiguous store state, refused \
                 rather than guessed"
            ),
            Self::Rejected(detail) => {
                write!(f, "the store rejected the request: {detail}")
            }
            Self::Other => f.write_str(
                "an unclassified upstream failure (upstream text is deliberately not carried)",
            ),
        }
    }
}

/// Reduces an upstream keyring error to the typed, byte-free
/// classification. Total, including the `#[non_exhaustive]` future.
fn classify_failure(error: &KeyringError) -> SecretServiceFailure {
    match error {
        KeyringError::NoStorageAccess(_) | KeyringError::NoDefaultStore => {
            SecretServiceFailure::Unavailable
        }
        KeyringError::PlatformFailure(_) => SecretServiceFailure::Unavailable,
        // Bytes discarded here: `BadEncoding`/`BadDataFormat` carry the
        // raw secret; `NoEntry` is intercepted as absence by every
        // caller and only reaches classification defensively.
        KeyringError::NoEntry | KeyringError::BadEncoding(_) | KeyringError::BadDataFormat(..) => {
            SecretServiceFailure::Undecodable
        }
        KeyringError::Ambiguous(entries) => SecretServiceFailure::Ambiguous(entries.len()),
        KeyringError::Invalid(parameter, detail) => {
            SecretServiceFailure::Rejected(format!("{parameter}: {detail}"))
        }
        KeyringError::TooLong(attribute, limit) => {
            SecretServiceFailure::Rejected(format!("{attribute} exceeds the store limit {limit}"))
        }
        KeyringError::BadStoreFormat(detail) | KeyringError::NotSupportedByStore(detail) => {
            SecretServiceFailure::Rejected(detail.clone())
        }
        _ => SecretServiceFailure::Other,
    }
}

/// The strict envelope parse (the `SessionEnvelopeStore::load` and
/// `parse_session_envelope` discipline): unknown fields via serde,
/// unsupported schema, digest integrity — refusals reduced to
/// kind+position, never the value (serde's Display embeds the offending
/// value verbatim).
fn parse_strict(bytes: &[u8]) -> Result<SessionEnvelope, WritableStoreError> {
    let envelope: SessionEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| SessionEnvelopeError::Parse(parse_error_summary(&error)))
        .map_err(WritableStoreError::Envelope)?;
    if envelope.schema_version != SESSION_SCHEMA_VERSION {
        return Err(WritableStoreError::Envelope(
            SessionEnvelopeError::UnsupportedSchema(envelope.schema_version),
        ));
    }
    if !envelope.verify_integrity() {
        return Err(WritableStoreError::Envelope(
            SessionEnvelopeError::Integrity,
        ));
    }
    Ok(envelope)
}

/// The guarded handoff shared by both stores: the embedded credentials
/// serialize into zeroizing transit and MOVE across the ingress seam.
fn credentials_through_boundary<S: SecretBoundary>(
    credentials: &serde_json::Value,
) -> Result<S, WritableStoreError> {
    let mut serialized = Zeroizing::new(serde_json::to_string(credentials).map_err(|error| {
        WritableStoreError::Envelope(SessionEnvelopeError::Parse(parse_error_summary(&error)))
    })?);
    Ok(S::ingress(mem::take(&mut *serialized)))
}

/// Every way a writable-store resolution or operation can refuse. No
/// payload ever carries credential bytes.
#[derive(Debug, thiserror::Error)]
pub enum WritableStoreError {
    /// An explicit `tpm2` was requested: post-M2 per m2-plan
    /// decision 2. Fail-closed, never a silent fallback (FR-7E) — the
    /// refusal names the variant and the deferred status.
    #[error(
        "the `{}` writable session store is not implemented in M2 (deferred post-M2, \
         m2-plan decision 2); refusing fail-closed rather than falling through to \
         another store (FR-7E)",
        .store.as_str()
    )]
    Deferred {
        /// The requested store variant.
        store: ConfiguredWritableStore,
    },
    /// An explicit `keyring` was requested but the Secret Service is
    /// not usable in this process (the injected availability said no:
    /// headless daemon, locked keyring, or no registered credential
    /// agent). Fail-closed exactly like [`WritableStoreError::Deferred`]
    /// — never a silent fallback (FR-7E).
    #[error(
        "the `keyring` writable session store was requested but the Secret Service is not \
         usable in this process (FR-7JA: the daemon reaches a desktop keyring only through \
         the registered credential agent); refusing fail-closed rather than falling through \
         to another store (FR-7E)"
    )]
    SecretServiceUnavailable,
    /// A Secret Service operation of the `keyring` store failed. The
    /// classification is typed and carries no credential bytes: the
    /// upstream error variants that embed raw secret bytes are reduced
    /// to their kind at the classification boundary, and upstream
    /// Display strings are never embedded (this enum's standing rule).
    #[error("secret service failure while {operation}: {failure}")]
    SecretService {
        /// The operation that failed.
        operation: SecretServiceOperation,
        /// The sanitized failure classification.
        failure: SecretServiceFailure,
    },
    /// `auto` walked the whole priority list without finding an
    /// implemented store. Refused rather than silently continuing as
    /// `none` — the FR-7EA confirmation requirement is the caller's to
    /// mint from this refusal.
    #[error(
        "`auto` found no implemented writable store in writable_store_priority \
         ({}); refusing rather than silently continuing as `none` — the FR-7EA \
         confirmation requirement is the caller's to mint",
        candidates.join(", ")
    )]
    NoImplementedStore {
        /// The exhausted candidates, as configured.
        candidates: Vec<String>,
    },
    /// The store's tree failed the fs_trust walk (symlink, wrong type,
    /// group/world write, non-root ownership).
    #[error("untrusted session-store tree: {0}")]
    Untrusted(#[from] FsTrustError),
    /// The envelope operation failed (I/O, size cap, parse, schema,
    /// integrity, stale generation) — the store-side typed refusals.
    #[error("writable session store failure: {0}")]
    Envelope(#[from] SessionEnvelopeError),
}

/// The peer-secret test double, mirroring the input half's: what
/// matters is that every value crosses `ingress` exactly once and is
/// read back only via `expose`.
#[cfg(test)]
mod test_support {
    use super::SecretBoundary;
    use std::cell::Cell;

    thread_local! {
        static INGRESS_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    #[derive(Clone)]
    pub(super) struct TestSecret(String);

    impl SecretBoundary for TestSecret {
        fn ingress(value: String) -> Self {
            INGRESS_CALLS.with(|calls| calls.set(calls.get() + 1));
            Self(value)
        }
        fn expose(&self) -> &str {
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
}

/// Vocabulary resolution: total, fail-closed, recorded skips.
#[cfg(test)]
mod resolution_tests {
    use super::*;

    fn paths(root: &Path) -> ConfigPaths {
        ConfigPaths::rooted(root)
    }

    fn account(priority: &[ConfiguredWritableStore]) -> AccountSection {
        AccountSection {
            writable_store_priority: priority.to_vec(),
            ..AccountSection::default()
        }
    }

    /// Totality, test-pinned: every spelling of the closed vocabulary
    /// has exactly one outcome under each availability, and the
    /// exhaustive match is compile-checked.
    #[test]
    fn every_spelling_of_the_vocabulary_resolves_totally() {
        let root = tempfile::tempdir().unwrap();
        let default = AccountSection::default();
        for (spelling, status, expected) in [
            (
                ConfiguredWritableStore::Auto,
                SecretServiceStatus::Available,
                "keyring",
            ),
            (
                ConfiguredWritableStore::Auto,
                SecretServiceStatus::Unavailable,
                "encrypted-local",
            ),
            (
                ConfiguredWritableStore::EncryptedLocal,
                SecretServiceStatus::Available,
                "encrypted-local",
            ),
            (
                ConfiguredWritableStore::EncryptedLocal,
                SecretServiceStatus::Unavailable,
                "encrypted-local",
            ),
            (
                ConfiguredWritableStore::None,
                SecretServiceStatus::Available,
                "memory",
            ),
            (
                ConfiguredWritableStore::None,
                SecretServiceStatus::Unavailable,
                "memory",
            ),
            (
                ConfiguredWritableStore::Keyring,
                SecretServiceStatus::Available,
                "keyring",
            ),
            (
                ConfiguredWritableStore::Keyring,
                SecretServiceStatus::Unavailable,
                "unavailable",
            ),
            (
                ConfiguredWritableStore::Tpm2,
                SecretServiceStatus::Available,
                "deferred",
            ),
            (
                ConfiguredWritableStore::Tpm2,
                SecretServiceStatus::Unavailable,
                "deferred",
            ),
        ] {
            let name = spelling.as_str();
            match resolve(spelling, &default, &paths(root.path()), status) {
                Ok(WritableStoreResolution {
                    store: ResolvedWritableStore::EncryptedLocal(_),
                    ..
                }) => assert_eq!(expected, "encrypted-local", "`{name}` misresolved"),
                Ok(WritableStoreResolution {
                    store: ResolvedWritableStore::Memory(_),
                    ..
                }) => assert_eq!(expected, "memory", "`{name}` misresolved"),
                // Lazy by construction: answering `keyring` binds no
                // D-Bus session, so this arm runs on every runner.
                Ok(WritableStoreResolution {
                    store: ResolvedWritableStore::Keyring(_),
                    ..
                }) => assert_eq!(expected, "keyring", "`{name}` misresolved"),
                Err(WritableStoreError::Deferred { .. }) => {
                    assert_eq!(expected, "deferred", "`{name}` misresolved")
                }
                Err(WritableStoreError::SecretServiceUnavailable) => {
                    assert_eq!(expected, "unavailable", "`{name}` misresolved")
                }
                other => panic!("`{name}` resolved outside the pinned outcomes: {other:?}"),
            }
        }
    }

    /// FR-7E/FR-7B: `auto` walks the DEFAULT priority (keyring, tpm2,
    /// encrypted-local). With the service available the keyring WINS
    /// (FR-7B's order) and only tpm2 is a typed skip; with it
    /// unavailable the keyring is the recorded skip and the walk falls
    /// through to encrypted-local.
    #[test]
    fn auto_prefers_the_secret_service_when_available_and_records_the_skips_when_not() {
        let root = tempfile::tempdir().unwrap();
        let resolution = resolve(
            ConfiguredWritableStore::Auto,
            &AccountSection::default(),
            &paths(root.path()),
            SecretServiceStatus::Available,
        )
        .expect("the default priority resolves to the keyring");
        assert!(matches!(
            resolution.store,
            ResolvedWritableStore::Keyring(_)
        ));
        assert!(
            resolution.skipped.is_empty(),
            "the walk stops at the first implemented candidate — the FR-7E record lists \
             only candidates passed OVER, and nothing precedes the keyring on the default \
             priority: {:?}",
            resolution.skipped
        );

        let resolution = resolve(
            ConfiguredWritableStore::Auto,
            &AccountSection::default(),
            &paths(root.path()),
            SecretServiceStatus::Unavailable,
        )
        .expect("encrypted-local is still reached");
        assert!(matches!(
            resolution.store,
            ResolvedWritableStore::EncryptedLocal(_)
        ));
        assert_eq!(
            resolution.skipped,
            vec![
                SkippedStore {
                    store: ConfiguredWritableStore::Keyring,
                    reason: SkipReason::SecretServiceUnavailable,
                },
                SkippedStore {
                    store: ConfiguredWritableStore::Tpm2,
                    reason: SkipReason::NotImplementedInM2,
                },
            ],
            "the unavailable keyring is a typed, ordered skip record"
        );
    }

    /// The S5c red-first pin, landed green: an explicit `keyring` with
    /// the service available RESOLVES (behavioral red before the
    /// variant existed: the S5b `Deferred` refusal panicked this
    /// test's ancestor). Lazy construction means resolution binds no
    /// D-Bus session — the live service is first touched by a store
    /// operation, in the process that owns the session bus.
    #[test]
    fn explicit_keyring_resolves_when_the_secret_service_is_available() {
        let root = tempfile::tempdir().unwrap();
        let resolution = resolve(
            ConfiguredWritableStore::Keyring,
            &AccountSection::default(),
            &paths(root.path()),
            SecretServiceStatus::Available,
        )
        .expect("keyring resolves when the secret service answers");
        assert!(
            matches!(resolution.store, ResolvedWritableStore::Keyring(_)),
            "the resolution is the keyring store: {:?}",
            resolution.store
        );
        assert!(resolution.skipped.is_empty());
    }

    /// FR-7E fail-closed: an explicit `keyring` under an unavailable
    /// service REFUSES with the typed unavailability — never a
    /// fallback, and the message names the store and the reason.
    #[test]
    fn explicit_keyring_refuses_when_the_secret_service_is_unavailable() {
        let root = tempfile::tempdir().unwrap();
        let default = AccountSection::default();
        match resolve(
            ConfiguredWritableStore::Keyring,
            &default,
            &paths(root.path()),
            SecretServiceStatus::Unavailable,
        ) {
            Err(WritableStoreError::SecretServiceUnavailable) => {}
            other => panic!("must refuse, not resolve or fall through: {other:?}"),
        }
        let message = resolve(
            ConfiguredWritableStore::Keyring,
            &default,
            &paths(root.path()),
            SecretServiceStatus::Unavailable,
        )
        .unwrap_err()
        .to_string();
        assert!(message.contains("keyring"), "the store is named: {message}");
        assert!(
            message.contains("not usable") && message.contains("FR-7E"),
            "the refusal states the unavailability and the no-fallback rule: {message}"
        );
    }

    /// FR-7E fail-closed (the post-M2 arm): an explicit `tpm2`
    /// REFUSES, naming the variant and the deferred status.
    #[test]
    fn explicit_tpm2_refuses_fail_closed_naming_the_variant() {
        let root = tempfile::tempdir().unwrap();
        let default = AccountSection::default();
        for status in [
            SecretServiceStatus::Available,
            SecretServiceStatus::Unavailable,
        ] {
            match resolve(
                ConfiguredWritableStore::Tpm2,
                &default,
                &paths(root.path()),
                status,
            ) {
                Err(WritableStoreError::Deferred { store }) => {
                    assert_eq!(store, ConfiguredWritableStore::Tpm2);
                }
                other => panic!("`tpm2` must refuse, not resolve or fall through: {other:?}"),
            }
        }
        let message = resolve(
            ConfiguredWritableStore::Tpm2,
            &default,
            &paths(root.path()),
            SecretServiceStatus::Available,
        )
        .unwrap_err()
        .to_string();
        assert!(message.contains("tpm2"), "the variant is named: {message}");
        assert!(
            message.contains("M2") && message.contains("post-M2"),
            "the deferred status is stated: {message}"
        );
    }

    /// The priority ORDER is honored: encrypted-local first -> no
    /// skips; tpm2 first -> exactly that skip recorded; keyring first
    /// with the service down -> the availability skip, then the fall
    /// through.
    #[test]
    fn auto_honors_the_priority_order() {
        let root = tempfile::tempdir().unwrap();
        let first = account(&[
            ConfiguredWritableStore::EncryptedLocal,
            ConfiguredWritableStore::Keyring,
        ]);
        let resolution = resolve(
            ConfiguredWritableStore::Auto,
            &first,
            &paths(root.path()),
            SecretServiceStatus::Available,
        )
        .expect("encrypted-local is implemented");
        assert!(
            resolution.skipped.is_empty(),
            "nothing is skipped before the first implemented candidate"
        );
        let second = account(&[
            ConfiguredWritableStore::Tpm2,
            ConfiguredWritableStore::EncryptedLocal,
        ]);
        let resolution = resolve(
            ConfiguredWritableStore::Auto,
            &second,
            &paths(root.path()),
            SecretServiceStatus::Unavailable,
        )
        .expect("encrypted-local is still reached");
        assert!(matches!(
            resolution.store,
            ResolvedWritableStore::EncryptedLocal(_)
        ));
        assert_eq!(
            resolution.skipped,
            vec![SkippedStore {
                store: ConfiguredWritableStore::Tpm2,
                reason: SkipReason::NotImplementedInM2,
            }]
        );
        let third = account(&[
            ConfiguredWritableStore::Keyring,
            ConfiguredWritableStore::EncryptedLocal,
        ]);
        let resolution = resolve(
            ConfiguredWritableStore::Auto,
            &third,
            &paths(root.path()),
            SecretServiceStatus::Unavailable,
        )
        .expect("encrypted-local is still reached");
        assert!(matches!(
            resolution.store,
            ResolvedWritableStore::EncryptedLocal(_)
        ));
        assert_eq!(
            resolution.skipped,
            vec![SkippedStore {
                store: ConfiguredWritableStore::Keyring,
                reason: SkipReason::SecretServiceUnavailable,
            }]
        );
    }

    /// FR-7EA's input: `auto` with no implemented candidate FAILS
    /// CLOSED naming the exhausted list — never a silent `none`.
    #[test]
    fn auto_without_an_implemented_candidate_refuses() {
        let root = tempfile::tempdir().unwrap();
        let only_deferred = account(&[
            ConfiguredWritableStore::Keyring,
            ConfiguredWritableStore::Tpm2,
        ]);
        match resolve(
            ConfiguredWritableStore::Auto,
            &only_deferred,
            &paths(root.path()),
            SecretServiceStatus::Unavailable,
        ) {
            Err(WritableStoreError::NoImplementedStore { candidates }) => {
                assert_eq!(candidates, ["keyring", "tpm2"]);
            }
            other => panic!("exhausted auto must refuse, got {other:?}"),
        }
        let message = resolve(
            ConfiguredWritableStore::Auto,
            &only_deferred,
            &paths(root.path()),
            SecretServiceStatus::Unavailable,
        )
        .unwrap_err()
        .to_string();
        assert!(
            message.contains("keyring, tpm2") && message.contains("none"),
            "the refusal names the candidates and the `none` question: {message}"
        );
    }

    /// `none` (FR-7EA): in-memory only — save/load round-trips within
    /// the process, and a FRESH instance starts empty (restart
    /// persistence unavailable by construction).
    #[test]
    fn none_resolves_in_memory_and_is_ephemeral() {
        let root = tempfile::tempdir().unwrap();
        let resolution = resolve(
            ConfiguredWritableStore::None,
            &AccountSection::default(),
            &paths(root.path()),
            SecretServiceStatus::Unavailable,
        )
        .expect("`none` always resolves");
        let ResolvedWritableStore::Memory(memory) = &resolution.store else {
            panic!("`none` must resolve to the memory store");
        };
        let envelope = SessionEnvelope::new(serde_json::json!({"AccessToken": "acc-mem"})).unwrap();
        memory.save(&envelope);
        assert_eq!(memory.load().as_ref(), Some(&envelope));
        // The uniform facade works; the fresh instance is empty.
        resolution.store.save(&envelope).unwrap();
        assert_eq!(resolution.store.load().unwrap().as_ref(), Some(&envelope));
        assert!(
            MemorySessionStore::default().load().is_none(),
            "a fresh instance starts empty"
        );
    }
}

/// The encrypted-local file store: derivation, atomic save, strict
/// load, guarded handoff. Positive strict-load arms need the walker's
/// root-owned tree and follow the suite's runner-gated skip pattern;
/// every refusal arm is provable unprivileged.
#[cfg(test)]
mod encrypted_local_tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::MetadataExt as _;
    use test_support::TestSecret;
    use test_support::ingresses;

    fn creds(token: &str) -> serde_json::Value {
        json!({
            "UID": "uid-1",
            "UserID": "user-1",
            "AccessToken": token,
            "RefreshToken": "refresh-1",
            "Scopes": ["loggedin", "full"],
        })
    }

    fn store(root: &Path) -> EncryptedLocalStore {
        EncryptedLocalStore::from_paths(&ConfigPaths::rooted(root))
    }

    /// Stages a valid envelope file directly (fixture independence: the
    /// load-refusal arms must measure the LOAD gates, not `save`).
    fn stage_envelope(store: &EncryptedLocalStore, envelope: &SessionEnvelope) {
        std::fs::create_dir_all(store.directory()).unwrap();
        std::fs::write(store.path(), serde_json::to_vec(envelope).unwrap()).unwrap();
    }

    /// The walker's ownership pass demands root:root.
    fn tree_is_root_owned(store: &EncryptedLocalStore) -> bool {
        std::fs::metadata(store.directory())
            .map(|meta| meta.uid() == 0 && meta.gid() == 0)
            .unwrap_or(false)
    }

    /// ConfigPaths-derived ONLY: production addresses
    /// /var/lib/protonwire/session.json, rooted tests address the tree
    /// under their root — and `from_paths` is the only constructor
    /// (structural: no path-injecting constructor exists to call).
    #[test]
    fn paths_come_from_config_paths_only() {
        assert_eq!(
            EncryptedLocalStore::from_paths(&ConfigPaths::system()).path(),
            Path::new("/var/lib/protonwire/session.json")
        );
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            store(root.path()).path(),
            &root.path().join("var/lib/protonwire/session.json")
        );
    }

    /// The saved file is owner-only 0600 AT CREATION, atomic, and
    /// leaves no temp residue (the delegated `SessionEnvelopeStore`
    /// save, pinned here for the writable-store contract).
    #[test]
    fn save_writes_owner_only_with_no_temp_residue() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        store
            .save(&SessionEnvelope::new(creds("acc-1")).unwrap())
            .unwrap();
        let path = store.path();
        assert_eq!(
            std::fs::metadata(path).unwrap().mode() & 0o777,
            0o600,
            "credentials file mode"
        );
        let directory = store.directory();
        let entries: Vec<std::ffi::OsString> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            [std::ffi::OsString::from("session.json")],
            "temp residue left behind: {entries:?}"
        );
    }

    /// The delegated monotonicity refusal: a stale writer cannot
    /// silently overwrite fresher credentials.
    #[test]
    fn save_enforces_generation_monotonicity() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        let base = SessionEnvelope::new(creds("acc-1")).unwrap();
        store.save(&base).unwrap();
        // Chain A pulls ahead: generations 2 and 3 land on disk.
        let ahead = base
            .regenerate(creds("acc-2"))
            .and_then(|envelope| envelope.regenerate(creds("acc-3")))
            .unwrap();
        store.save(&ahead).unwrap();
        // Chain B — a stale writer regenerating from the same base —
        // now writes generation 2 against on-disk 3: refused.
        let stale = base.regenerate(creds("acc-b2")).unwrap();
        match store.save(&stale) {
            Err(WritableStoreError::Envelope(SessionEnvelopeError::StaleGeneration {
                attempted,
                on_disk,
            })) => assert_eq!((attempted, on_disk), (2, 3)),
            other => panic!("expected StaleGeneration, got {other:?}"),
        }
    }

    /// A missing file is `None` — an empty store, not an error.
    #[test]
    fn load_of_a_missing_file_is_none() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(store(root.path()).load().unwrap(), None);
    }

    /// FD-pinning (S5a sec P3 discipline): a symlinked leaf fails AT
    /// OPEN — the typed symlink refusal, target never consulted.
    #[test]
    fn load_refuses_a_symlinked_leaf() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        stage_envelope(&store, &SessionEnvelope::new(creds("acc-1")).unwrap());
        let real = store.directory().join("real-session.json");
        std::fs::rename(store.path(), &real).unwrap();
        std::os::unix::fs::symlink(&real, store.path()).unwrap();
        let err = store.load().unwrap_err();
        assert!(
            matches!(
                err,
                WritableStoreError::Untrusted(FsTrustError::Symlink { .. })
            ),
            "must be the symlink defect: {err}"
        );
    }

    /// The store's directory is inside the walk: a group-writable
    /// /var/lib/protonwire lets any local user plant the envelope file.
    #[test]
    fn load_refuses_a_world_writable_store_directory() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        stage_envelope(&store, &SessionEnvelope::new(creds("acc-1")).unwrap());
        std::fs::set_permissions(store.directory(), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        let err = store.load().unwrap_err();
        assert!(
            matches!(
                err,
                WritableStoreError::Untrusted(FsTrustError::GroupWorldWritable { .. })
            ),
            "must be the directory's mode defect: {err}"
        );
    }

    /// Stat-first size gate: a hostile file is refused on SIZE before a
    /// single byte is read.
    #[test]
    fn load_refuses_oversized_documents() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        std::fs::create_dir_all(store.directory()).unwrap();
        std::fs::write(store.path(), vec![b'x'; MAX_SESSION_BYTES + 1]).unwrap();
        match store.load() {
            Err(WritableStoreError::Envelope(SessionEnvelopeError::Parse(message))) => {
                assert!(
                    message.contains("size cap"),
                    "the refusal names the cap: {message}"
                );
            }
            other => panic!("expected the size-cap Parse refusal, got {other:?}"),
        }
    }

    /// The strict parse: unknown schema versions and tampered digests
    /// refuse fail-closed (never migrate or best-effort credentials).
    #[test]
    fn load_refuses_unknown_schema_and_tampered_integrity() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        std::fs::create_dir_all(store.directory()).unwrap();
        let envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        let future = json!({
            "schema_version": SESSION_SCHEMA_VERSION + 1,
            "envelope_generation": 1,
            "source_digest": envelope.source_digest,
            "credentials": creds("acc-1"),
        });
        std::fs::write(store.path(), serde_json::to_vec(&future).unwrap()).unwrap();
        match store.load() {
            Err(WritableStoreError::Envelope(SessionEnvelopeError::UnsupportedSchema(version))) => {
                assert_eq!(version, SESSION_SCHEMA_VERSION + 1)
            }
            other => panic!("expected UnsupportedSchema, got {other:?}"),
        }
        let mut tampered = envelope.clone();
        tampered.credentials = creds("attacker-swap");
        std::fs::write(store.path(), serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(matches!(
            store.load(),
            Err(WritableStoreError::Envelope(
                SessionEnvelopeError::Integrity
            ))
        ));
    }

    /// The ownership arm: a tree that is not the root-owned
    /// /var/lib/protonwire tree is refused. Unprivileged runners
    /// construct it for free; root runners hand it to uid/gid 65534.
    #[test]
    fn load_refuses_a_non_root_owned_tree() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        stage_envelope(&store, &SessionEnvelope::new(creds("acc-1")).unwrap());
        let directory = store.directory();
        if std::fs::metadata(directory).unwrap().uid() == 0 {
            let _ = std::os::unix::fs::chown(directory, Some(65534), Some(65534));
        }
        if std::fs::metadata(directory).unwrap().uid() == 0 {
            return; // cannot construct a non-root-owned tree here
        }
        let err = store.load().unwrap_err();
        assert!(
            matches!(
                err,
                WritableStoreError::Untrusted(FsTrustError::NotRootOwned { .. })
            ),
            "must be the ownership defect: {err}"
        );
    }

    /// The full round trip through the STRICT load (root-gated: the
    /// walker's ownership pass).
    #[test]
    fn round_trip_through_the_strict_load() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        let envelope = SessionEnvelope::new(creds("acc-rt")).unwrap();
        store.save(&envelope).unwrap();
        if !tree_is_root_owned(&store) {
            // NOTICE skip (CONTRIBUTING rule 5, the 8867777 idiom): the
            // fs_trust ownership arm needs a root-owned tree, which an
            // unprivileged runner cannot construct; visible via
            // `cargo test -- --nocapture`.
            eprintln!(
                "NOTICE: round_trip_through_the_strict_load skipped — the fs_trust \
                 ownership arm needs a root-owned /var/lib/protonwire tree"
            );
            return;
        }
        assert_eq!(store.load().unwrap().as_ref(), Some(&envelope));
    }

    /// The guarded handoff (root-gated on-disk arm): the credentials
    /// cross the ingress boundary EXACTLY ONCE, moved from zeroizing
    /// transit, and load performs no expose of its own.
    #[test]
    fn on_disk_credentials_cross_ingress_exactly_once() {
        let root = tempfile::tempdir().unwrap();
        let store = store(root.path());
        let envelope = SessionEnvelope::new(creds("acc-handoff")).unwrap();
        store.save(&envelope).unwrap();
        if !tree_is_root_owned(&store) {
            // NOTICE skip (the 8867777 idiom): same ownership-arm bound
            // as the round trip above; the exactly-once discipline
            // itself is pinned unprivileged by the memory arm below.
            eprintln!(
                "NOTICE: on_disk_credentials_cross_ingress_exactly_once skipped — the \
                 fs_trust ownership arm needs a root-owned /var/lib/protonwire tree"
            );
            return;
        }
        let before = ingresses();
        let secret: TestSecret = store
            .load_credentials()
            .unwrap()
            .expect("an envelope is on disk");
        assert_eq!(
            ingresses() - before,
            1,
            "the value crosses ingress exactly once"
        );
        assert_eq!(
            secret.expose(),
            serde_json::to_string(&creds("acc-handoff")).unwrap()
        );
        assert_eq!(format!("{secret:?}"), "[redacted-test]");
    }

    /// The unprivileged handoff arm, through the memory store: the same
    /// exactly-once ingress discipline without the walker.
    #[test]
    fn memory_credentials_cross_ingress_exactly_once() {
        let memory = MemorySessionStore::default();
        memory.save(&SessionEnvelope::new(creds("acc-mem")).unwrap());
        let before = ingresses();
        let secret: TestSecret = memory
            .load_credentials()
            .expect("the in-memory envelope is present");
        assert_eq!(
            ingresses() - before,
            1,
            "the value crosses ingress exactly once"
        );
        assert_eq!(
            secret.expose(),
            serde_json::to_string(&creds("acc-mem")).unwrap()
        );
    }
}

/// The Secret Service store (S5c): every behavioral arm runs against
/// the keyring-core MOCK store injected through
/// [`KeyringSessionStore::with_store`] — no D-Bus daemon is needed or
/// contacted anywhere in this module (CI runners have no Secret
/// Service; the mock is in-memory and per-test). The live zbus arm's
/// one environment-gated refusal pin lives at the bottom.
#[cfg(test)]
mod keyring_store_tests {
    use super::*;
    use serde_json::json;
    use test_support::TestSecret;
    use test_support::ingresses;

    fn creds(token: &str) -> serde_json::Value {
        json!({
            "UID": "uid-1",
            "UserID": "user-1",
            "AccessToken": token,
            "RefreshToken": "refresh-1",
            "Scopes": ["loggedin", "full"],
        })
    }

    /// A fresh in-memory Secret Service plus the store bound to it.
    /// Each test gets its OWN mock store (the `with_store` seam): no
    /// shared entry, no cross-test interference, no process-global
    /// default-store mutation.
    fn mock_store() -> (Arc<CredentialStore>, KeyringSessionStore) {
        // `Store::new` hands back the shared Arc directly (the mock
        // store's own shape), coerced to the store trait object.
        let store: Arc<CredentialStore> =
            keyring_core::mock::Store::new().expect("the mock store builds");
        (Arc::clone(&store), KeyringSessionStore::with_store(store))
    }

    /// Stages RAW bytes as the session entry (fixture independence: the
    /// strict-load arms measure the LOAD gates, not `save`).
    fn stage_raw(store: &Arc<CredentialStore>, bytes: &[u8]) {
        let entry = store
            .build(KEYRING_SERVICE, KEYRING_USER, None)
            .expect("the mock store builds the entry");
        entry.set_secret(bytes).expect("the mock store takes bytes");
    }

    /// The round trip through the mock Secret Service, including a
    /// regeneration (the rewrite path a token refresh takes).
    #[test]
    fn round_trips_the_envelope_through_the_secret_service() {
        let (_mock, store) = mock_store();
        assert_eq!(store.load().unwrap(), None, "a fresh service holds nothing");
        let envelope = SessionEnvelope::new(creds("acc-kr-1")).unwrap();
        store.save(&envelope).unwrap();
        assert_eq!(store.load().unwrap().as_ref(), Some(&envelope));
        let rewritten = envelope.regenerate(creds("acc-kr-2")).unwrap();
        store.save(&rewritten).unwrap();
        assert_eq!(store.load().unwrap().as_ref(), Some(&rewritten));
    }

    /// The uniform facade works over the keyring arm with the mock
    /// store — the enum dispatch S9 consumes, pinned D-Bus-free.
    #[test]
    fn the_resolved_facade_round_trips_the_keyring_arm() {
        let (_mock, store) = mock_store();
        let resolved = ResolvedWritableStore::Keyring(store);
        let envelope = SessionEnvelope::new(creds("acc-facade")).unwrap();
        resolved.save(&envelope).unwrap();
        assert_eq!(resolved.load().unwrap().as_ref(), Some(&envelope));
        let secret: TestSecret = resolved.load_credentials().unwrap().unwrap();
        assert_eq!(
            secret.expose(),
            serde_json::to_string(&creds("acc-facade")).unwrap()
        );
    }

    /// The delegated monotonicity refusal (the file store's rule, same
    /// floor): a stale writer cannot silently overwrite fresher
    /// credentials, and the fresher envelope survives the refusal.
    #[test]
    fn save_enforces_generation_monotonicity() {
        let (_mock, store) = mock_store();
        let base = SessionEnvelope::new(creds("acc-1")).unwrap();
        store.save(&base).unwrap();
        // Chain A pulls ahead: generations 2 and 3 land in the service.
        let ahead = base
            .regenerate(creds("acc-2"))
            .and_then(|envelope| envelope.regenerate(creds("acc-3")))
            .unwrap();
        store.save(&ahead).unwrap();
        // Chain B — a stale writer regenerating from the same base —
        // now writes generation 2 against the service's 3: refused.
        let stale = base.regenerate(creds("acc-b2")).unwrap();
        match store.save(&stale) {
            Err(WritableStoreError::Envelope(SessionEnvelopeError::StaleGeneration {
                attempted,
                on_disk,
            })) => assert_eq!((attempted, on_disk), (2, 3)),
            other => panic!("expected StaleGeneration, got {other:?}"),
        }
        assert_eq!(
            store.load().unwrap().unwrap().envelope_generation,
            3,
            "the fresher envelope survives the refused write"
        );
    }

    /// The strict parse against service bytes: unknown schema,
    /// tampered digest, and garbage each refuse fail-closed — never a
    /// best-effort envelope. Staged raw so the arms measure `load`.
    #[test]
    fn load_refuses_unknown_schema_tampered_integrity_and_garbage() {
        let (mock, store) = mock_store();
        let envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        let future = json!({
            "schema_version": SESSION_SCHEMA_VERSION + 1,
            "envelope_generation": 1,
            "source_digest": envelope.source_digest,
            "credentials": creds("acc-1"),
        });
        stage_raw(&mock, &serde_json::to_vec(&future).unwrap());
        match store.load() {
            Err(WritableStoreError::Envelope(SessionEnvelopeError::UnsupportedSchema(version))) => {
                assert_eq!(version, SESSION_SCHEMA_VERSION + 1)
            }
            other => panic!("expected UnsupportedSchema, got {other:?}"),
        }
        let mut tampered = envelope.clone();
        tampered.credentials = creds("attacker-swap");
        stage_raw(&mock, &serde_json::to_vec(&tampered).unwrap());
        assert!(matches!(
            store.load(),
            Err(WritableStoreError::Envelope(
                SessionEnvelopeError::Integrity
            ))
        ));
        stage_raw(&mock, b"{ not json");
        assert!(matches!(
            store.load(),
            Err(WritableStoreError::Envelope(SessionEnvelopeError::Parse(_)))
        ));
    }

    /// The size cap: an oversized service blob refuses on load (the
    /// file store's shared gate; post-allocation here — see
    /// [`KeyringSessionStore::read_bytes`]).
    #[test]
    fn load_refuses_oversized_service_blobs() {
        let (mock, store) = mock_store();
        stage_raw(&mock, &vec![b'x'; MAX_SESSION_BYTES + 1]);
        match store.load() {
            Err(WritableStoreError::Envelope(SessionEnvelopeError::Parse(message))) => {
                assert!(
                    message.contains("size cap"),
                    "the refusal names the cap: {message}"
                );
            }
            other => panic!("expected the size-cap Parse refusal, got {other:?}"),
        }
    }

    /// The guarded handoff (mock arm, unprivileged-friendly): the
    /// credentials cross the ingress boundary EXACTLY ONCE, moved from
    /// zeroizing transit, and the store's own Debug never renders them.
    #[test]
    fn keyring_credentials_cross_ingress_exactly_once_and_debug_stays_clean() {
        let (_mock, store) = mock_store();
        let envelope = SessionEnvelope::new(creds("acc-kr-handoff")).unwrap();
        store.save(&envelope).unwrap();
        let rendered = format!("{store:?}");
        for fragment in ["acc-kr-handoff", "refresh-1", "uid-1", "user-1"] {
            assert!(
                !rendered.contains(fragment),
                "the store's Debug must never render credential bytes ({fragment}): {rendered}"
            );
        }
        assert!(
            rendered.contains(KEYRING_SERVICE) && rendered.contains(KEYRING_USER),
            "the entry identity stays named: {rendered}"
        );
        let before = ingresses();
        let secret: TestSecret = store
            .load_credentials()
            .unwrap()
            .expect("an envelope is in the service");
        assert_eq!(
            ingresses() - before,
            1,
            "the value crosses ingress exactly once"
        );
        assert_eq!(
            secret.expose(),
            serde_json::to_string(&creds("acc-kr-handoff")).unwrap()
        );
        assert_eq!(format!("{secret:?}"), "[redacted-test]");
    }

    /// The typed classification: every upstream error class reduces to
    /// its byte-free kind, and the refusal's Display carries no
    /// credential bytes — `BadEncoding` embeds them upstream.
    #[test]
    fn the_classification_is_typed_and_never_carries_secret_bytes() {
        let secret_bytes = b"\xff\xfe-acc-classify-secret".to_vec();
        for (upstream, expected) in [
            (
                KeyringError::BadEncoding(secret_bytes.clone()),
                SecretServiceFailure::Undecodable,
            ),
            (
                KeyringError::BadDataFormat(secret_bytes.clone(), "probe".into()),
                SecretServiceFailure::Undecodable,
            ),
            (
                KeyringError::NoStorageAccess("locked".into()),
                SecretServiceFailure::Unavailable,
            ),
            (
                KeyringError::PlatformFailure("no bus".into()),
                SecretServiceFailure::Unavailable,
            ),
            (
                KeyringError::NoDefaultStore,
                SecretServiceFailure::Unavailable,
            ),
            (
                KeyringError::Ambiguous(Vec::new()),
                SecretServiceFailure::Ambiguous(0),
            ),
            (
                KeyringError::Invalid("parameter".into(), "detail".into()),
                SecretServiceFailure::Rejected("parameter: detail".into()),
            ),
            (
                KeyringError::TooLong("attribute".into(), 42),
                SecretServiceFailure::Rejected("attribute exceeds the store limit 42".into()),
            ),
        ] {
            assert_eq!(
                classify_failure(&upstream),
                expected,
                "misclassified {upstream:?}"
            );
            let refusal = WritableStoreError::SecretService {
                operation: SecretServiceOperation::Load,
                failure: classify_failure(&upstream),
            }
            .to_string();
            assert!(
                !refusal.contains("acc-classify-secret"),
                "the refusal leaked the secret bytes: {refusal}"
            );
        }
    }

    /// The operation failure path through the live types: an injected
    /// mock error surfaces as the typed, byte-free refusal naming the
    /// operation.
    #[test]
    fn an_injected_store_error_surfaces_typed() {
        let (mock, store) = mock_store();
        store
            .save(&SessionEnvelope::new(creds("acc-1")).unwrap())
            .unwrap();
        let staged = mock
            .build(KEYRING_SERVICE, KEYRING_USER, None)
            .expect("the entry exists");
        let credential = staged
            .as_any()
            .downcast_ref::<keyring_core::mock::Cred>()
            .expect("the mock store's credential is the mock cred");
        credential.set_error(KeyringError::Invalid(
            "probe-param".into(),
            "probe-detail".into(),
        ));
        match store.load() {
            Err(WritableStoreError::SecretService {
                operation: SecretServiceOperation::Load,
                failure: SecretServiceFailure::Rejected(detail),
            }) => {
                assert!(
                    detail.contains("probe-param") && detail.contains("probe-detail"),
                    "the platform detail (non-secret) is carried: {detail}"
                );
            }
            other => panic!("expected the typed SecretService refusal, got {other:?}"),
        }
        // The mock's error is one-shot: the next operation recovers.
        assert!(store.load().unwrap().is_some());
    }

    /// The one LIVE-arm pin, environment-gated (CONTRIBUTING rule 5):
    /// on a runner with NO session bus (stock CI), binding the real
    /// zbus store must refuse with the typed unavailability — the
    /// fail-closed answer for a headless process. On a developer box
    /// with a live session bus the assertion cannot be constructed, so
    /// it NOTICE-skips.
    #[test]
    fn a_busless_runner_refuses_the_live_bind_typed() {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
            eprintln!(
                "NOTICE: a_busless_runner_refuses_the_live_bind_typed skipped — this \
                 runner has a session bus; the refusal arm is proven on busless CI"
            );
            return;
        }
        let store = KeyringSessionStore::new();
        match store.load() {
            Err(WritableStoreError::SecretService {
                operation: SecretServiceOperation::Bind,
                failure: SecretServiceFailure::Unavailable,
            }) => {}
            other => panic!("expected the typed bind refusal, got {other:?}"),
        }
    }
}
