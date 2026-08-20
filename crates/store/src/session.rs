//! Versioned Muon session envelope with atomic persistence (FR-7C, M2 S4).
//!
//! This is the ProtonWire-owned persistence format for Muon session
//! credentials — deliberately a *distinct document* from anything a
//! future ProTUN `ApiSession` cache would define (FR-7C): its schema is
//! ours, its versioning is ours, and it never shares a file with
//! ProTUN-owned session state. The envelope *wraps* the serialized Muon
//! `SessionCredentials` verbatim (the wire's PascalCase
//! `UID`/`UserID`/`AccessToken`/`RefreshToken`/`Scopes` object — spike
//! memo Q2), carried as embedded JSON so this crate stays free of any
//! Muon type (the adapter crate, the single place upstream API changes
//! land, produces and consumes the embedded value).
//!
//! Envelope fields:
//!
//! * `schema_version` — this format's version; a reader that does not
//!   recognize it fails closed rather than guessing (never migrate
//!   credentials silently).
//! * `envelope_generation` — bumped on every rewrite (login, token
//!   refresh, fork import), so a stale write is distinguishable from
//!   the current one even when both parse.
//! * `source_digest` — SHA-256 over the canonical serialization of the
//!   embedded credentials, binding the generation counter to the exact
//!   payload it attests (integrity of the pair, not secrecy: the file
//!   is mode 0600 and its contents are still credentials).
//!
//! Persistence follows the `state.rs` precedent: write a sibling temp
//! file, fsync, rename over the target — with the one hardening this
//! document needs over the daemon state file: the temp file is created
//! with mode `0600`, because a partially-written credentials file is
//! still a credentials file.

use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use serde::Deserialize;
use serde::Serialize;

/// Size ceiling for the session document: the wrapped credentials object
/// is a few hundred bytes; 64 KiB is generous headroom while keeping a
/// hostile or corrupted file from being read whole into memory.
pub const MAX_SESSION_BYTES: usize = 64 * 1024;

/// The schema version of this envelope format (FR-7C).
pub const SESSION_SCHEMA_VERSION: u32 = 1;

/// Distinct temp-file counter (the `state.rs` precedent): concurrent
/// saves in different threads never share an inode.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// The versioned envelope around serialized Muon session credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEnvelope {
    /// The envelope format version ([`SESSION_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Monotonic rewrite counter; starts at 1.
    pub envelope_generation: u64,
    /// SHA-256 (hex) over the canonical serialization of `credentials`.
    pub source_digest: String,
    /// The serialized Muon `SessionCredentials`, verbatim.
    pub credentials: serde_json::Value,
}

/// Failures of the session envelope store.
#[derive(Debug, thiserror::Error)]
pub enum SessionEnvelopeError {
    /// Reading or writing failed.
    #[error("session store I/O failure: {0}")]
    Io(#[from] io::Error),
    /// The document failed validation.
    #[error("invalid session document: {0}")]
    Parse(String),
    /// The document is a schema this reader does not know.
    #[error("unsupported session schema version: {0}")]
    UnsupportedSchema(u32),
    /// The digest does not match the embedded credentials.
    #[error("session envelope integrity failure")]
    Integrity,
    /// The write would regress `envelope_generation` below the valid
    /// envelope already on disk — a stale writer must not silently
    /// overwrite fresher credentials (rust P2, S4 review round).
    #[error("stale envelope generation: attempted {attempted}, on disk {on_disk}")]
    StaleGeneration { attempted: u64, on_disk: u64 },
}

impl SessionEnvelope {
    /// Wraps `credentials` as generation 1.
    ///
    /// # Errors
    /// Returns [`SessionEnvelopeError::Parse`] if `credentials` cannot
    /// be serialized canonically.
    pub fn new(credentials: serde_json::Value) -> Result<Self, SessionEnvelopeError> {
        Self::at_generation(1, credentials)
    }

    /// The next generation wrapping `credentials`: same schema, bumped
    /// `envelope_generation`, fresh digest. Token refreshes and fork
    /// imports rewrite through this so a persisted generation always
    /// attests exactly the payload it was written with.
    ///
    /// # Errors
    /// Returns [`SessionEnvelopeError::Parse`] if `credentials` cannot
    /// be serialized canonically.
    pub fn regenerate(&self, credentials: serde_json::Value) -> Result<Self, SessionEnvelopeError> {
        Self::at_generation(self.envelope_generation + 1, credentials)
    }

    /// The one constructor: digest the canonical serialization, bind it
    /// to `generation`.
    fn at_generation(
        generation: u64,
        credentials: serde_json::Value,
    ) -> Result<Self, SessionEnvelopeError> {
        let source_digest = canonical_digest(&credentials)?;
        Ok(Self {
            schema_version: SESSION_SCHEMA_VERSION,
            envelope_generation: generation,
            source_digest,
            credentials,
        })
    }

    /// True when `source_digest` matches the canonical digest of the
    /// embedded credentials (the integrity the loader enforces).
    pub fn verify_integrity(&self) -> bool {
        self.source_digest == canonical_digest(&self.credentials).unwrap_or_default()
    }

    /// The embedded serialized credentials (the value to hand back to
    /// Muon).
    #[must_use]
    pub fn credentials(&self) -> &serde_json::Value {
        &self.credentials
    }
}

/// Reduces a serde error to its KIND and POSITION: `json data error at
/// line 1 column 50`. The message text is dropped because serde's
/// `invalid type` Display prints the offending VALUE — a password in a
/// misprovisioned slot would land verbatim in the error string (S5a
/// rust-review FAIL P1, identical arm probed there; this file's twin
/// is fixed by the S5a lane).
fn parse_error_kind_at(e: serde_json::Error) -> String {
    format!(
        "json {:?} error at line {} column {}",
        e.classify(),
        e.line(),
        e.column()
    )
}

/// Hex SHA-256 over the canonical (compact) serialization of `value`.
fn canonical_digest(value: &serde_json::Value) -> Result<String, SessionEnvelopeError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| SessionEnvelopeError::Parse(parse_error_kind_at(e)))?;
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(&bytes);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Atomic read/modify/write access to the session envelope file, per the
/// `state.rs` precedent (`StateStore`).
#[derive(Debug, Clone)]
pub struct SessionEnvelopeStore {
    path: PathBuf,
}

impl SessionEnvelopeStore {
    /// Opens (without creating) the store at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The envelope file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads the envelope; a missing file is `None`. Rejects unknown
    /// schemas, unknown fields, oversized documents, and digest
    /// mismatches — every one fail-closed.
    ///
    /// # Errors
    /// See [`SessionEnvelopeError`].
    pub fn load(&self) -> Result<Option<SessionEnvelope>, SessionEnvelopeError> {
        // Stat first (rust Low, S4 review round): a hostile multi-
        // gigabyte file is refused on SIZE before `fs::read` allocates
        // for it. The post-read cap below stays — the file may grow
        // between the two calls.
        match std::fs::metadata(&self.path) {
            Ok(meta) if meta.len() > MAX_SESSION_BYTES as u64 => {
                return Err(SessionEnvelopeError::Parse(
                    "session document exceeds size cap".into(),
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() > MAX_SESSION_BYTES {
            return Err(SessionEnvelopeError::Parse(
                "session document exceeds size cap".into(),
            ));
        }
        let envelope: SessionEnvelope = serde_json::from_slice(&bytes)
            .map_err(|e| SessionEnvelopeError::Parse(parse_error_kind_at(e)))?;
        if envelope.schema_version != SESSION_SCHEMA_VERSION {
            return Err(SessionEnvelopeError::UnsupportedSchema(
                envelope.schema_version,
            ));
        }
        if !envelope.verify_integrity() {
            return Err(SessionEnvelopeError::Integrity);
        }
        Ok(Some(envelope))
    }

    /// Persists the envelope atomically: sibling temp file (mode 0600),
    /// fsync, rename over the target.
    ///
    /// Monotonicity (rust P2, S4 review round): a write whose
    /// `envelope_generation` is below the valid on-disk envelope's is
    /// REFUSED before anything is written — a stale writer regenerating
    /// from superseded state must not silently overwrite fresher
    /// credentials. The floor is only the readable, integral
    /// predecessor: a missing file imposes none, and an unreadable one
    /// fails the save rather than laundering a blind overwrite.
    /// Residual: the compare-then-rename sequence is not atomic across
    /// concurrent writers (equal generations race; single-writer
    /// pinning is the S5 facade's to add on top).
    ///
    /// # Errors
    /// See [`SessionEnvelopeError`].
    pub fn save(&self, envelope: &SessionEnvelope) -> Result<(), SessionEnvelopeError> {
        if let Some(on_disk) = self.load()?
            && envelope.envelope_generation < on_disk.envelope_generation
        {
            return Err(SessionEnvelopeError::StaleGeneration {
                attempted: envelope.envelope_generation,
                on_disk: on_disk.envelope_generation,
            });
        }
        let bytes = serde_json::to_vec(envelope)
            .map_err(|e| SessionEnvelopeError::Parse(parse_error_kind_at(e)))?;
        if bytes.len() > MAX_SESSION_BYTES {
            return Err(SessionEnvelopeError::Parse(
                "session document exceeds size cap".into(),
            ));
        }
        let parent = self.path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let tmp = parent.join(format!(
            ".{}.tmp-{}-{}",
            self.path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("session"),
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    // Mode AT CREATION (rust Low, S4 review round): an
                    // empty world-readable temp file used to exist
                    // between create and the set_permissions below;
                    // 0600-from-the-first-instant closes that window (a
                    // umask can only narrow it further).
                    .mode(0o600)
                    .open(&tmp)?
            }
            #[cfg(not(unix))]
            {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp)?
            }
        };
        // A partially-written credentials file is still a credentials
        // file: owner-only regardless of umask (the explicit set can
        // only normalize toward 0600, never widen it).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn creds(token: &str) -> serde_json::Value {
        json!({
            "UID": "uid-1",
            "UserID": "user-1",
            "AccessToken": token,
            "RefreshToken": "refresh-1",
            "Scopes": ["loggedin", "full"],
        })
    }

    #[test]
    fn new_envelope_is_generation_one_with_matching_digest() {
        let envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        assert_eq!(envelope.schema_version, SESSION_SCHEMA_VERSION);
        assert_eq!(envelope.envelope_generation, 1);
        assert!(envelope.verify_integrity());
        assert_eq!(envelope.credentials(), &creds("acc-1"));
    }

    #[test]
    fn regenerate_bumps_generation_and_rebinds_the_digest() {
        let first = SessionEnvelope::new(creds("acc-1")).unwrap();
        let second = first.regenerate(creds("acc-2")).unwrap();
        assert_eq!(second.envelope_generation, 2);
        assert!(second.verify_integrity());
        assert_eq!(second.credentials(), &creds("acc-2"));
        // The generations are distinguishable even ignoring content.
        assert_ne!(first.source_digest, second.source_digest);
    }

    #[test]
    fn tampered_credentials_fail_integrity() {
        let mut envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        envelope.credentials = creds("attacker-swap");
        assert!(!envelope.verify_integrity());
    }

    #[test]
    fn round_trip_is_atomic_and_leaves_no_temp_residue() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionEnvelopeStore::new(dir.path().join("session.json"));
        assert_eq!(store.load().unwrap(), None);

        let envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        store.save(&envelope).unwrap();
        assert_eq!(store.load().unwrap().as_ref(), Some(&envelope));

        let rewritten = envelope.regenerate(creds("acc-2")).unwrap();
        store.save(&rewritten).unwrap();
        assert_eq!(store.load().unwrap().as_ref(), Some(&rewritten));

        let entries: Vec<std::ffi::OsString> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            [std::ffi::OsString::from("session.json")],
            "temp residue left behind: {entries:?}"
        );
    }

    #[test]
    fn the_saved_file_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let store = SessionEnvelopeStore::new(&path);
        store
            .save(&SessionEnvelope::new(creds("acc-1")).unwrap())
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "credentials file mode {mode:o}");
        }
    }

    #[test]
    fn regressed_generation_is_refused_against_the_on_disk_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let store = SessionEnvelopeStore::new(dir.path().join("session.json"));

        let base = SessionEnvelope::new(creds("acc-1")).unwrap();
        store.save(&base).unwrap();

        // Chain A pulls ahead: generations 2 and 3 land on disk.
        let a2 = base.regenerate(creds("acc-a2")).unwrap();
        let a3 = a2.regenerate(creds("acc-a3")).unwrap();
        store.save(&a2).unwrap();
        store.save(&a3).unwrap();

        // Chain B — a stale writer regenerating from the same base —
        // now writes generation 2 against on-disk 3: refused, and the
        // fresher envelope survives untouched.
        let b2 = base.regenerate(creds("acc-b2")).unwrap();
        match store.save(&b2) {
            Err(SessionEnvelopeError::StaleGeneration { attempted, on_disk }) => {
                assert_eq!((attempted, on_disk), (2, 3));
            }
            other => panic!("expected StaleGeneration, got {other:?}"),
        }
        let loaded = store.load().unwrap().expect("envelope present");
        assert_eq!(loaded.envelope_generation, 3);
        assert_eq!(loaded.credentials(), &creds("acc-a3"));
    }

    /// The racing arm of the monotonicity pin: two threads regenerate
    /// independent chains from one shared base and save concurrently.
    /// In lockstep rounds the generations are EQUAL (not below) — both
    /// writers' atomic renames must succeed — and once one chain is
    /// ahead, the lagging chain's next write is refused as a
    /// regression. (Single-writer pinning is the S5 facade's to add;
    /// until then the compare-before-rename refusal is the guard, and
    /// its residual compare/rename race is exactly what the facade
    /// closes.)
    #[test]
    fn racing_regenerate_chains_refuse_the_regressed_writer() {
        const ROUNDS: u64 = 8;
        let dir = tempfile::tempdir().unwrap();
        let store = SessionEnvelopeStore::new(dir.path().join("session.json"));

        let base = SessionEnvelope::new(creds("acc-base")).unwrap();
        store.save(&base).unwrap();

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut chains = Vec::new();
        for t in 0..2 {
            let store = store.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            let mut chain = base.clone();
            chains.push(std::thread::spawn(move || {
                for r in 1..=ROUNDS {
                    chain = chain
                        .regenerate(json!({
                            "UID": format!("uid-r{r}-{t}"),
                            "UserID": "user",
                            "AccessToken": format!("acc-r{r}-{t}"),
                            "RefreshToken": "refresh",
                            "Scopes": ["loggedin"],
                        }))
                        .unwrap();
                    // Lockstep: both threads hold generation r+1 before
                    // either saves — equal generations race the rename,
                    // and BOTH saves must succeed (not-below passes).
                    barrier.wait();
                    store.save(&chain).expect("equal-generation save");
                }
                chain
            }));
        }
        let finished: Vec<_> = chains.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(
            store.load().unwrap().unwrap().envelope_generation,
            ROUNDS + 1
        );

        // One chain pulls ahead by two generations; the other's next
        // write is below on-disk and must be refused.
        let ahead = finished[0]
            .regenerate(creds("acc-ahead-1"))
            .and_then(|e| e.regenerate(creds("acc-ahead-2")))
            .unwrap();
        store.save(&ahead).unwrap();
        let lagging = finished[1].regenerate(creds("acc-lagging")).unwrap();
        match store.save(&lagging) {
            Err(SessionEnvelopeError::StaleGeneration { attempted, on_disk }) => {
                assert_eq!((attempted, on_disk), (ROUNDS + 2, ROUNDS + 3));
            }
            other => panic!("expected StaleGeneration, got {other:?}"),
        }
        let loaded = store.load().unwrap().expect("envelope present");
        assert_eq!(loaded.envelope_generation, ROUNDS + 3);
        assert_eq!(loaded.credentials(), &creds("acc-ahead-2"));
    }

    #[test]
    fn future_schema_versions_are_rejected_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        let future = serde_json::json!({
            "schema_version": SESSION_SCHEMA_VERSION + 1,
            "envelope_generation": 1,
            "source_digest": envelope.source_digest,
            "credentials": creds("acc-1"),
        });
        std::fs::write(&path, serde_json::to_vec(&future).unwrap()).unwrap();
        match SessionEnvelopeStore::new(&path).load() {
            Err(SessionEnvelopeError::UnsupportedSchema(v)) => assert_eq!(v, 2),
            other => panic!("expected UnsupportedSchema, got {other:?}"),
        }
    }

    #[test]
    fn digest_mismatch_is_rejected_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let mut envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        envelope.credentials = creds("tampered");
        std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        match SessionEnvelopeStore::new(&path).load() {
            Err(SessionEnvelopeError::Integrity) => {}
            other => panic!("expected Integrity failure, got {other:?}"),
        }
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        let mut doc = serde_json::to_value(&envelope).unwrap();
        doc["protun_session"] = serde_json::json!("never share a schema with ProTUN (FR-7C)");
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(matches!(
            SessionEnvelopeStore::new(&path).load(),
            Err(SessionEnvelopeError::Parse(_))
        ));
    }

    #[test]
    fn oversized_documents_are_refused_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let store = SessionEnvelopeStore::new(&path);
        // Huge embedded value: serialize-limited on save...
        let mut huge = serde_json::Value::Object(Default::default());
        huge["blob"] = serde_json::Value::String("x".repeat(MAX_SESSION_BYTES));
        match SessionEnvelope::new(huge) {
            Err(SessionEnvelopeError::Parse(_)) => {}
            Ok(envelope) => {
                // ...and byte-limited if it somehow fits the in-memory cap.
                assert!(matches!(
                    store.save(&envelope),
                    Err(SessionEnvelopeError::Parse(_))
                ));
            }
            other => panic!("expected Parse, got {other:?}"),
        }
        // ...and read-limited on load.
        std::fs::write(&path, vec![b'x'; MAX_SESSION_BYTES + 1]).unwrap();
        assert!(matches!(store.load(), Err(SessionEnvelopeError::Parse(_))));
    }

    #[test]
    fn corrupted_document_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(matches!(
            SessionEnvelopeStore::new(&path).load(),
            Err(SessionEnvelopeError::Parse(_))
        ));
    }

    /// S5a rust-review FAIL P1 (identical arm, probed there): serde's
    /// `invalid type` Display prints the offending VALUE — a password
    /// in a misprovisioned slot landed verbatim in the error string.
    /// The Parse refusal must carry kind and position only, never the
    /// value. Pre-fix red: the message was `invalid type: string
    /// "hunter2-super-secret-password", expected u32 ...`.
    #[test]
    fn parse_refusals_never_embed_the_offending_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        // Misprovisioned: `schema_version` (a u32) carrying a
        // password-shaped probe string, first in the document so the
        // type error is the parse failure.
        let doc = concat!(
            r#"{"schema_version": "hunter2-super-secret-password","#,
            r#""envelope_generation": 1,"#,
            r#""source_digest": "00","#,
            r#""credentials": {}}"#
        );
        std::fs::write(&path, doc).unwrap();
        match SessionEnvelopeStore::new(&path).load() {
            Err(SessionEnvelopeError::Parse(message)) => {
                assert!(
                    !message.contains("hunter2-super-secret-password"),
                    "the offending value leaked into the parse refusal: {message}"
                );
                assert!(
                    message.contains("line 1 column"),
                    "the refusal must still name the position: {message}"
                );
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    /// The wrap-the-serialized-credentials contract (spike memo Q2): the
    /// envelope's embedded value is byte-for-byte Muon's PascalCase
    /// `SessionCredentials` serialization, produced by the adapter crate.
    /// The adapter-side integration test (`protonwire-api`
    /// `tests/wire.rs`) round-trips a real Muon `Auth` through this
    /// envelope; this test pins the in-store shape so the two crates
    /// cannot drift: PascalCase keys, no extra wrapping object.
    #[test]
    fn embedded_credentials_keep_the_muon_wire_shape() {
        let envelope = SessionEnvelope::new(creds("acc-1")).unwrap();
        let doc = serde_json::to_value(&envelope).unwrap();
        let embedded = &doc["credentials"];
        for key in ["UID", "UserID", "AccessToken", "RefreshToken", "Scopes"] {
            assert!(embedded.get(key).is_some(), "missing {key} in {embedded}");
        }
    }
}

/// Concurrency arm: the `state.rs` finding-13 pattern applied here —
/// concurrent saves must all succeed atomically with no temp residue.
#[cfg(test)]
mod concurrent_save_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn concurrent_saves_are_atomic_and_leave_no_temp_residue() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.json");
        let store = SessionEnvelopeStore::new(path.clone());
        const THREADS: usize = 8;
        const SAVES_EACH: usize = 25;

        let mut handles = Vec::new();
        for t in 0..THREADS {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..SAVES_EACH {
                    let creds = json!({
                        "UID": format!("uid-{t}"),
                        "UserID": "user",
                        "AccessToken": format!("acc-{i}"),
                        "RefreshToken": "refresh",
                        "Scopes": ["loggedin"],
                    });
                    store
                        .save(&SessionEnvelope::new(creds).unwrap())
                        .expect("every concurrent save must succeed");
                }
            }));
        }
        for handle in handles {
            handle.join().expect("no saver may panic");
        }

        let loaded = store.load().expect("final envelope must parse");
        let envelope = loaded.expect("an envelope must exist");
        assert!(envelope.verify_integrity());
        let entries: Vec<std::ffi::OsString> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            [std::ffi::OsString::from("session.json")],
            "temp residue left behind: {entries:?}"
        );
    }
}
