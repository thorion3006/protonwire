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

/// Hex SHA-256 over the canonical (compact) serialization of `value`.
fn canonical_digest(value: &serde_json::Value) -> Result<String, SessionEnvelopeError> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| SessionEnvelopeError::Parse(e.to_string()))?;
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
            .map_err(|e| SessionEnvelopeError::Parse(e.to_string()))?;
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
    /// # Errors
    /// See [`SessionEnvelopeError`].
    pub fn save(&self, envelope: &SessionEnvelope) -> Result<(), SessionEnvelopeError> {
        let bytes =
            serde_json::to_vec(envelope).map_err(|e| SessionEnvelopeError::Parse(e.to_string()))?;
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
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        // A partially-written credentials file is still a credentials
        // file: owner-only from the first byte.
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
