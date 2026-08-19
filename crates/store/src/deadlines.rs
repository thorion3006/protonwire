//! Persisted scheduler deadlines and suppression (FR-13H, M2 S7).
//!
//! The single-flight metadata scheduler's restart-surviving state: the
//! last metadata request time, the effective interval source, the next
//! automatic refresh time, the wall-clock high-water mark that arms the
//! rollback guard, any `Retry-After` suppression deadline, and the
//! automatic/manual diagnostic counters (FR-13I). Everything the
//! scheduler must not forget across a daemon restart lives here —
//! by design that includes the state that makes both **manual bypass**
//! and **clock rollback** unable to revive an early refresh (T-26,
//! E2E-22).
//!
//! Placement mirrors [`crate::catalog`]: a small strict JSON document
//! under the cache directory, loaded only through the fs_trust walk
//! (production `trust_root` is `/`; the daemon runs as root over a
//! root-owned tree) and written atomically per the [`crate::state`]
//! precedent (sibling temp file, fsync, rename). Tampering with this
//! file could weaken suppression into a Proton rate-limiting incident,
//! so the walk rejects symlinked/writable/non-root components exactly
//! like the catalog cache.
//!
//! One deliberate absence: **confirmation tokens are never persisted**
//! (FR-13I — approval is not a preference; `deny_unknown_fields` makes
//! a smuggled token field a hard parse error).

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::fs_trust::{self, MissingLeaf};

/// Schema version of the deadlines document.
pub const DEADLINES_SCHEMA_VERSION: u32 = 1;

/// Size ceiling for the deadlines document. The document is a handful of
/// integers; 4 KiB is orders of magnitude beyond any legitimate value and
/// still trivially small.
pub const MAX_DEADLINES_BYTES: usize = 4 * 1024;

/// Which component won the greatest-of that set the effective deadline
/// (FR-13D/FR-13H: the "effective interval source" must persist across
/// restarts so status can explain why the next refresh is when it is).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntervalSource {
    /// The configured refresh interval won.
    Configured,
    /// The three-hour product floor won (FR-12).
    ThreeHourFloor,
    /// A Proton-provided cache lifetime won.
    ProtonLifetime,
    /// A `Retry-After` signal won the greatest-of (spike memo Q4).
    RetryAfter,
}

/// The persisted scheduler state document (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerDeadlines {
    /// Schema version of the document.
    pub schema_version: u32,
    /// Unix time of the last upstream metadata request, whatever its
    /// outcome (`None` until the first request ever).
    pub last_request_unix: Option<u64>,
    /// Unix time of the last *successful* fetch (changed or not-modified)
    /// — the catalog-age anchor for the FR-11 confirmation envelope.
    pub last_success_unix: Option<u64>,
    /// The next automatic-refresh eligibility time (greatest-of plus
    /// non-negative jitter); `None` before the first request (the FR-13F
    /// bootstrap fetch is immediately due).
    pub next_eligible_unix: Option<u64>,
    /// Which greatest-of component set [`Self::next_eligible_unix`].
    pub next_eligible_source: Option<IntervalSource>,
    /// The highest wall-clock reading ever persisted. Clock rollback is
    /// detected against it: a current wall reading below the high-water
    /// mark is untrustworthy, and every persisted absolute deadline
    /// remains in force until the wall catches back up (T-26 — a
    /// rolled-back clock must not trigger an immediate-refetch storm).
    pub wall_high_water_unix: u64,
    /// The `Retry-After` suppression deadline (greatest-of with the
    /// three-hour floor, spike memo Q4). Even a confirmed manual refresh
    /// is refused before it (E2E-22); `None` when no suppression is
    /// active.
    pub suppression_until_unix: Option<u64>,
    /// Completed automatic refreshes since the first run (diagnostics,
    /// FR-123/E2E-22).
    pub automatic_refresh_count: u64,
    /// Completed confirmed manual overrides since the first run
    /// (diagnostics, counted separately per FR-13I).
    pub manual_refresh_count: u64,
}

impl Default for SchedulerDeadlines {
    fn default() -> Self {
        Self {
            schema_version: DEADLINES_SCHEMA_VERSION,
            last_request_unix: None,
            last_success_unix: None,
            next_eligible_unix: None,
            next_eligible_source: None,
            wall_high_water_unix: 0,
            suppression_until_unix: None,
            automatic_refresh_count: 0,
            manual_refresh_count: 0,
        }
    }
}

/// Failures of the deadline store.
#[derive(Debug, thiserror::Error)]
pub enum DeadlineStoreError {
    /// Reading or writing failed.
    #[error("deadline store I/O failure: {0}")]
    Io(#[from] std::io::Error),
    /// The fs_trust walk rejected a path component.
    #[error("deadline store path is not trusted: {0}")]
    FsTrust(#[from] fs_trust::FsTrustError),
    /// The document exceeds the size cap.
    #[error("deadline document of {0} bytes exceeds the {MAX_DEADLINES_BYTES}-byte limit")]
    TooLarge(usize),
    /// The document is structurally invalid or has the wrong schema
    /// version (including unknown fields — a confirmation token must not
    /// be persistable, FR-13I).
    #[error("invalid deadline document: {0}")]
    Malformed(String),
}

/// Distinct temp-file counter (the [`crate::state`] atomic-write
/// precedent: concurrent writers get distinct siblings).
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Atomic strict-loaded store for [`SchedulerDeadlines`] (the
/// [`crate::catalog::CatalogCache`] pattern applied to scheduler state).
#[derive(Debug, Clone)]
pub struct DeadlineStore {
    path: PathBuf,
}

impl DeadlineStore {
    /// Opens the store at `path` (created on first [`Self::save`]).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The store file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Strictly loads the deadlines: the fs_trust walk (leaf to
    /// `trust_root`, missing leaf allowed) runs before any read, then the
    /// document is validated (schema version, full field set). A missing
    /// file is `Ok(None)`. This is the production loader — `/` is the
    /// production `trust_root`.
    pub fn load_strict(
        &self,
        trust_root: &Path,
    ) -> Result<Option<SchedulerDeadlines>, DeadlineStoreError> {
        fs_trust::verify_trusted_path(&self.path, trust_root, MissingLeaf::Allow)?;
        self.load_validated()
    }

    /// The read+validate body of the load, after a caller has established
    /// path trust. Private: outside callers get [`Self::load_strict`].
    fn load_validated(&self) -> Result<Option<SchedulerDeadlines>, DeadlineStoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() > MAX_DEADLINES_BYTES {
            return Err(DeadlineStoreError::TooLarge(bytes.len()));
        }
        let doc: SchedulerDeadlines = serde_json::from_slice(&bytes)
            .map_err(|e| DeadlineStoreError::Malformed(e.to_string()))?;
        if doc.schema_version != DEADLINES_SCHEMA_VERSION {
            return Err(DeadlineStoreError::Malformed(format!(
                "deadline schema version {} != {DEADLINES_SCHEMA_VERSION}",
                doc.schema_version
            )));
        }
        Ok(Some(doc))
    }

    /// Atomically persists `doc`: sibling temp file (mode 0644), fsync,
    /// rename — the [`crate::state`] precedent.
    pub fn save(&self, doc: &SchedulerDeadlines) -> Result<(), DeadlineStoreError> {
        let mut doc = doc.clone();
        doc.schema_version = DEADLINES_SCHEMA_VERSION;
        let bytes = serde_json::to_vec_pretty(&doc)
            .map_err(|e| DeadlineStoreError::Malformed(e.to_string()))?;
        if bytes.len() > MAX_DEADLINES_BYTES {
            return Err(DeadlineStoreError::TooLarge(bytes.len()));
        }
        let parent = self.path.parent().unwrap_or(Path::new(".")).to_path_buf();
        create_cache_dir(&parent)?;
        let tmp = parent.join(format!(
            ".{}.tmp-{}-{}",
            self.path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("deadlines"),
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Creates the parent directory and any missing ancestors with mode 0755
/// (the [`crate::catalog`] precedent: never chmod existing dirs).
fn create_cache_dir(path: &Path) -> Result<(), DeadlineStoreError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o755);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn deadlines() -> SchedulerDeadlines {
        SchedulerDeadlines {
            schema_version: DEADLINES_SCHEMA_VERSION,
            last_request_unix: Some(1_771_000_000),
            last_success_unix: Some(1_771_000_000),
            next_eligible_unix: Some(1_771_010_800),
            next_eligible_source: Some(IntervalSource::ThreeHourFloor),
            wall_high_water_unix: 1_771_000_000,
            suppression_until_unix: None,
            automatic_refresh_count: 4,
            manual_refresh_count: 1,
        }
    }

    #[test]
    fn round_trips_every_persisted_deadline_fact() {
        let dir = tempfile::tempdir().unwrap();
        let store = DeadlineStore::new(dir.path().join("deadlines.json"));
        store.save(&deadlines()).unwrap();
        let loaded = store.load_validated().unwrap().expect("persisted entry");
        assert_eq!(loaded, deadlines());
    }

    #[test]
    fn missing_file_loads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = DeadlineStore::new(dir.path().join("deadlines.json"));
        assert!(store.load_validated().unwrap().is_none());
    }

    /// FR-13I from the persistence side: approval is never a preference,
    /// and the document type must not grow a token field silently —
    /// `deny_unknown_fields` makes a smuggled token (or any drift) a
    /// hard error.
    #[test]
    fn unknown_fields_are_rejected_including_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deadlines.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&deadlines()).unwrap().replace(
                "\"manual_refresh_count\": 1",
                "\"manual_refresh_count\": 1,\n  \"confirmation_token\": \"abc\"",
            ),
        )
        .unwrap();
        let err = DeadlineStore::new(&path).load_validated().unwrap_err();
        assert!(matches!(err, DeadlineStoreError::Malformed(_)), "{err}");
        assert!(err.to_string().contains("confirmation_token"), "{err}");
    }

    #[test]
    fn wrong_schema_version_fails_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deadlines.json");
        let mut stale = serde_json::to_value(deadlines()).unwrap();
        stale["schema_version"] = serde_json::json!(0);
        std::fs::write(&path, serde_json::to_vec_pretty(&stale).unwrap()).unwrap();
        let err = DeadlineStore::new(&path).load_validated().unwrap_err();
        assert!(matches!(err, DeadlineStoreError::Malformed(_)), "{err}");
        assert!(err.to_string().contains("schema"), "{err}");
    }

    /// A truncated document (fields missing) is a hard error, not a
    /// defaults-filled guess: the rollback guard's high-water mark must
    /// never silently reset to 0.
    #[test]
    fn missing_fields_fail_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deadlines.json");
        std::fs::write(&path, b"{\"schema_version\":1}").unwrap();
        let err = DeadlineStore::new(&path).load_validated().unwrap_err();
        assert!(matches!(err, DeadlineStoreError::Malformed(_)), "{err}");
    }

    #[test]
    fn oversized_documents_are_rejected_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deadlines.json");
        std::fs::write(&path, vec![b'x'; MAX_DEADLINES_BYTES + 1]).unwrap();
        let err = DeadlineStore::new(&path).load_validated().unwrap_err();
        assert!(matches!(err, DeadlineStoreError::TooLarge(_)), "{err}");
    }

    #[test]
    fn save_is_atomic_and_leaves_no_residue() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deadlines.json");
        let store = DeadlineStore::new(path.clone());
        store.save(&deadlines()).unwrap();
        store.save(&deadlines()).unwrap();
        let entries: Vec<std::ffi::OsString> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, [std::ffi::OsString::from("deadlines.json")]);
    }

    /// The full strict loader (walk + validated load) happy path, run
    /// only where the runner can construct a root-owned tree — the same
    /// compromise as the catalog cache's strict-load tests.
    #[test]
    fn strict_load_walks_then_loads_for_root_runners() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deadlines.json");
        let store = DeadlineStore::new(path.clone());
        store.save(&deadlines()).unwrap();
        let root_owned = std::fs::metadata(&path)
            .map(|m| m.uid() == 0 && m.gid() == 0)
            .unwrap_or(false);
        if !root_owned {
            return; // ownership arm unprovable for this runner
        }
        let loaded = store
            .load_strict(dir.path())
            .unwrap()
            .expect("persisted entry");
        assert_eq!(loaded.wall_high_water_unix, 1_771_000_000);
    }

    #[test]
    fn strict_load_rejects_a_symlinked_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        let link = dir.path().join("deadlines.json");
        DeadlineStore::new(&real).save(&deadlines()).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = DeadlineStore::new(link.clone())
            .load_strict(dir.path())
            .unwrap_err();
        assert!(matches!(err, DeadlineStoreError::FsTrust(_)), "{err}");
    }

    #[test]
    fn strict_load_rejects_a_writable_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deadlines.json");
        let store = DeadlineStore::new(path.clone());
        store.save(&deadlines()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = store.load_strict(dir.path()).unwrap_err();
        assert!(matches!(err, DeadlineStoreError::FsTrust(_)), "{err}");
    }

    #[test]
    fn write_sets_no_group_or_world_bits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deadlines.json");
        DeadlineStore::new(path.clone()).save(&deadlines()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o022,
            0,
            "deadline file must not be group/world writable, got {mode:o}"
        );
    }
}
