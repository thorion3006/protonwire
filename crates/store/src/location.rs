//! The persisted user-location cache (M2 S10 / T-31: provenance + the
//! three-hour floor).
//!
//! The user-location payload (the api crate's `location` module, sent
//! through the Muon transport per the S10 contract) is cached with its
//! provenance — when it was fetched — and a PURE three-hour floor
//! predicate the policy layer composes: T-31's "persisted three-hour
//! location-request suppression" is `location_request_due` applied to
//! the persisted `fetched_unix`, so a restart cannot re-request inside
//! the floor either (the persisted-provenance rule, FR-13H's class).
//!
//! ## Why this cache is 0600 when the catalog precedent is 0644
//!
//! THE RATIONALE (state the SEC-16-class reason): the catalog cache is
//! PUBLIC server data — every local account may read it, so 0644 is
//! correct there. THIS document carries the USER'S PUBLIC IP AND ISP
//! — identifying data whose disclosure to every local account is a
//! privacy defect (SEC-16-class at rest: "protect secrets and
//! sensitive data at rest and in transit"). The leaf is therefore
//! owner-only (0600) at write time, verified by test; the strict
//! loader additionally walks the path (root-owned, no group/world
//! write, symlink-free) exactly like the catalog cache, so neither
//! tampering nor disclosure has a path. The directory rule is the
//! catalog's (0755 create, existing dirs never chmod'd — the leaf's
//! 0600 is what protects the payload).
//!
//! ## Document discipline
//!
//! [`CachedLocation`] is ProtonWire's OWN document format (not the
//! upstream wire): explicit fields, `deny_unknown_fields`, no
//! defaults — a drifted or hand-edited document is a hard
//! [`LocationCacheError::Malformed`], the [`crate::catalog`]
//! precedent. The model mirrors the upstream payload fields (ip,
//! country, isp, optional coordinates); conversion from the api
//! crate's model happens at the composition seam, deliberately not
//! here (this crate does not depend on the api crate).
//!
//! ## Deliberate boundaries of this unit
//!
//! NO scheduling and NO daemon wiring (m2-plan S10's boundary for this
//! slice): single-flight, on-demand-only-when-needed, Retry-After and
//! block honoring, and `physical-country-required` composition belong
//! to the policy/daemon lanes. This module provides the persisted
//! document, its strict loader, its 0600 atomic writer, and the pure
//! floor predicate — nothing reads a clock and nothing performs I/O
//! outside `load_strict`/`store`.

use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::fs_trust::{MissingLeaf, verify_trusted_path};

/// The location cache document's schema version.
pub const LOCATION_CACHE_SCHEMA_VERSION: u32 = 1;

/// The persisted three-hour location-request floor (T-31): after a
/// location fetch, the next request is not due until
/// `fetched_unix + FLOOR` — the product floor FR-12 states for
/// automatic metadata, applied to the on-demand location read by the
/// S10 policy. The PREDICATE is pure ([`location_request_due`]); the
/// enforcement (suppression that outranks even a confirmed manual
/// refresh, `Retry-After` composition) is the scheduler's, never
/// here.
pub const LOCATION_REQUEST_FLOOR_SECONDS: u64 = 3 * 60 * 60;

/// Upper bound for the persisted location document. The payload is a
/// few hundred bytes; 8 KiB is generous headroom while refusing
/// anything planted or corrupted wholesale.
pub const MAX_LOCATION_BYTES: usize = 8 * 1024;

/// The leaf mode every cache write applies (the module's 0600
/// rationale: the payload carries the user's public IP and ISP).
pub const LOCATION_CACHE_MODE: u32 = 0o600;

/// The persisted user-location document: the payload facts plus their
/// provenance. `ip`/`isp` are identifying data — see the module's
/// 0600 rationale — so the `Debug` is manual and redacts them (the
/// api-side model's rule, applied to this document too: a `tracing`
/// field or `{:?}` of a loaded cache can never carry the user's IP or
/// ISP).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedLocation {
    /// Cache schema version.
    pub schema_version: u32,
    /// When this payload was fetched (Unix seconds) — the provenance
    /// the three-hour floor anchors to.
    pub fetched_unix: u64,
    /// The user's public IP at fetch time (wire `IP`, verbatim).
    pub ip: String,
    /// The user's ISO country code (wire `Country`) — the
    /// physical-country feature's datum (FR-23L).
    pub country: String,
    /// The user's ISP (wire `ISP`).
    pub isp: String,
    /// The latitude (wire `Lat`); absent stays absent.
    pub latitude: Option<f32>,
    /// The longitude (wire `Long`); absent stays absent.
    pub longitude: Option<f32>,
}

/// IP discipline on the persisted document: `ip` and `isp` never
/// render (the api-side model's rule); only the coarse facts and the
/// provenance do.
impl std::fmt::Debug for CachedLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedLocation")
            .field("schema_version", &self.schema_version)
            .field("fetched_unix", &self.fetched_unix)
            .field("ip", &"[redacted]")
            .field("country", &self.country)
            .field("isp", &"[redacted]")
            .field("latitude", &self.latitude)
            .field("longitude", &self.longitude)
            .finish()
    }
}

/// Failures of the location cache (the [`crate::catalog`] taxonomy).
#[derive(Debug, thiserror::Error)]
pub enum LocationCacheError {
    /// Reading or writing failed.
    #[error("location cache I/O failure: {0}")]
    Io(#[from] std::io::Error),
    /// The fs_trust walk rejected a path component.
    #[error("location cache path is not trusted: {0}")]
    FsTrust(#[from] crate::fs_trust::FsTrustError),
    /// The cached document exceeds a cap.
    #[error("location cache of {0} bytes exceeds the {MAX_LOCATION_BYTES}-byte limit")]
    TooLarge(usize),
    /// The cached document is structurally invalid or has the wrong
    /// schema version (upstream drift fails loudly, not approximately).
    #[error("invalid location cache: {0}")]
    Malformed(String),
}

/// Distinct temp-file counter (the [`crate::state`] atomic-write
/// precedent: concurrent writers get distinct siblings).
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Atomic 0600 store for the user location (typically `location.json`
/// inside [`crate::paths::ConfigPaths::cache_dir`]).
#[derive(Debug, Clone)]
pub struct LocationCache {
    path: PathBuf,
}

impl LocationCache {
    /// Opens the cache at `path` (created on first [`Self::store`]).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The cache file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Strictly loads the cache: the fs_trust walk (leaf to
    /// `trust_root`, missing leaf allowed) runs before any read, then
    /// the document is validated. A missing cache is `Ok(None)` — the
    /// legitimate never-fetched state (the floor predicate then says
    /// a request is due). This is the production loader — the daemon
    /// runs as root over a root-owned `/var/cache/protonwire` tree.
    ///
    /// # Errors
    /// [`LocationCacheError::FsTrust`] when the path is untrusted,
    /// [`LocationCacheError::TooLarge`] over the cap,
    /// [`LocationCacheError::Malformed`] on drift, including a wrong
    /// schema version or an unknown key.
    pub fn load_strict(
        &self,
        trust_root: &Path,
    ) -> Result<Option<CachedLocation>, LocationCacheError> {
        verify_trusted_path(&self.path, trust_root, MissingLeaf::Allow)?;
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() > MAX_LOCATION_BYTES {
            return Err(LocationCacheError::TooLarge(bytes.len()));
        }
        let cached: CachedLocation = serde_json::from_slice(&bytes)
            .map_err(|e| LocationCacheError::Malformed(e.to_string()))?;
        if cached.schema_version != LOCATION_CACHE_SCHEMA_VERSION {
            return Err(LocationCacheError::Malformed(format!(
                "cache schema version {} != {LOCATION_CACHE_SCHEMA_VERSION}",
                cached.schema_version
            )));
        }
        Ok(Some(cached))
    }

    /// Atomically stores `doc`: sibling temp file (mode 0600 — THE
    /// difference from the catalog precedent, see the module's
    /// rationale: this payload carries the user's public IP and ISP),
    /// fsync, rename — the [`crate::state`] atomic-write precedent.
    /// The size cap is enforced post-serialization (a file the loader
    /// would reject must never be written).
    ///
    /// # Errors
    /// [`LocationCacheError::TooLarge`] over the cap;
    /// [`LocationCacheError::Io`] on any I/O failure.
    pub fn store(&self, doc: &CachedLocation) -> Result<(), LocationCacheError> {
        let bytes =
            serde_json::to_vec(doc).map_err(|e| LocationCacheError::Malformed(e.to_string()))?;
        if bytes.len() > MAX_LOCATION_BYTES {
            return Err(LocationCacheError::TooLarge(bytes.len()));
        }
        let parent = self.path.parent().unwrap_or(Path::new(".")).to_path_buf();
        std::fs::create_dir_all(&parent)?;
        let tmp = parent.join(format!(
            ".{}.tmp-{}-{}",
            self.path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("location"),
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(LOCATION_CACHE_MODE)
                .open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// The pure three-hour floor predicate (T-31): is a location REQUEST
/// due at `now_unix`, given the last fetch's provenance? `None` (never
/// fetched, or no cache) is always due — the bootstrap; otherwise due
/// exactly AT `fetched + floor` (the boundary-resumes rule). No clock
/// reads, no I/O: the scheduler composes this with its suppression and
/// jitter machinery; the daemon composes it with the on-demand-only
/// wiring (neither is this module's).
#[must_use]
pub fn location_request_due(last_fetch_unix: Option<u64>, now_unix: u64) -> bool {
    match last_fetch_unix {
        None => true,
        Some(fetched) => now_unix >= fetched.saturating_add(LOCATION_REQUEST_FLOOR_SECONDS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> CachedLocation {
        CachedLocation {
            schema_version: LOCATION_CACHE_SCHEMA_VERSION,
            fetched_unix: 1_771_000_000,
            // RFC 5737 documentation address, never a real one.
            ip: "192.0.2.1".to_owned(),
            country: "IS".to_owned(),
            isp: "Synthetic Test ISP".to_owned(),
            latitude: Some(64.1466),
            longitude: Some(-21.9426),
        }
    }

    /// The document round-trip through the FILE (no trust walk — that
    /// half is root-gated below): the stored bytes parse back into the
    /// same document, proving serialize/deserialize agree.
    #[test]
    fn the_stored_document_round_trips_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let cache = LocationCache::new(dir.path().join("location.json"));
        cache.store(&doc()).unwrap();
        let bytes = std::fs::read(cache.path()).unwrap();
        let parsed: CachedLocation = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, doc());
    }

    /// The strict-load happy path (walk + load + equality). Root-gated
    /// (the catalog suite's compromise, verbatim — the a368775 NOTICE
    /// idiom): the walk's ownership pass needs a root-owned tree, which
    /// an unprivileged runner cannot construct; the walk's mode and
    /// symlink arms are covered unprivileged below.
    #[test]
    fn strict_load_round_trips_for_root_runners() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let cache = LocationCache::new(dir.path().join("location.json"));
        // Gate on the TREE's ownership up front: an unprivileged runner
        // cannot pass the walk's ownership pass for any existing
        // component, so the whole strict path is root-only here.
        let root_owned = std::fs::metadata(dir.path())
            .map(|m| m.uid() == 0 && m.gid() == 0)
            .unwrap_or(false);
        if !root_owned {
            eprintln!(
                "NOTICE: skipping strict_load_round_trips_for_root_runners: the cache \
                 tree is not root-owned on this runner — the ownership arm of the \
                 fs_trust walk is unprovable unprivileged (the file round-trip is \
                 pinned unprivileged by the_stored_document_round_trips_through_the_file)"
            );
            return;
        }
        assert_eq!(
            cache
                .load_strict(dir.path())
                .expect("absent cache is clean"),
            None,
            "a missing cache is the never-fetched state"
        );
        cache.store(&doc()).unwrap();
        let loaded = cache
            .load_strict(dir.path())
            .expect("the stored document loads strict")
            .expect("and is present");
        assert_eq!(loaded, doc());
    }

    /// THE 0600 PIN (the module's rationale, enforced): the leaf is
    /// owner-only — the payload carries the user's public IP and ISP,
    /// and the catalog precedent's 0644 would disclose them to every
    /// local account. Red observed against the catalog-precedent copy
    /// (mode 0644): the assert failed with mode 0o644.
    #[test]
    fn the_cache_leaf_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let cache = LocationCache::new(dir.path().join("location.json"));
        cache.store(&doc()).unwrap();
        let mode = std::fs::metadata(cache.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "the IP-bearing payload must be owner-only at rest (the SEC-16 \
             rationale) — pinned as the LITERAL, not the write constant: \
             weakening LOCATION_CACHE_MODE must fail here, not flip both \
             sides of the comparison (the S10 review's constant-anchor gap)"
        );
    }

    /// The pure floor predicate: the bootstrap is due, the window is
    /// not, the boundary resumes exactly AT the floor, and a saturated
    /// (hostile-top-of-range) fetch timestamp pins the deadline at
    /// u64::MAX — never wrapped into the past.
    #[test]
    fn the_three_hour_floor_predicate() {
        let fetched = 1_771_000_000_u64;
        assert!(location_request_due(None, 0), "never fetched: due");
        assert!(
            !location_request_due(Some(fetched), fetched + LOCATION_REQUEST_FLOOR_SECONDS - 1),
            "inside the floor: not due"
        );
        assert!(
            location_request_due(Some(fetched), fetched + LOCATION_REQUEST_FLOOR_SECONDS),
            "the boundary resumes exactly AT the floor"
        );
        assert!(
            !location_request_due(Some(u64::MAX), fetched),
            "a saturated fetch timestamp never wraps into a due deadline"
        );
    }

    /// Drift fails loudly at the DOCUMENT level (deny_unknown_fields,
    /// no defaults — direct serde, no I/O): an unknown key, a missing
    /// required field, and a wrong-typed field are each hard parse
    /// errors. The loader's schema-version check rides the root-gated
    /// strict-load test.
    #[test]
    fn document_drift_fails_loudly() {
        let good = serde_json::to_string(&doc()).unwrap();

        let mut value: serde_json::Value = serde_json::from_str(&good).unwrap();
        value["Wappa"] = serde_json::json!(1);
        assert!(
            serde_json::from_value::<CachedLocation>(value).is_err(),
            "an unknown key must fail to parse"
        );

        let mut value: serde_json::Value = serde_json::from_str(&good).unwrap();
        value.as_object_mut().unwrap().remove("fetched_unix");
        assert!(
            serde_json::from_value::<CachedLocation>(value).is_err(),
            "a missing required field must fail"
        );

        let mut value: serde_json::Value = serde_json::from_str(&good).unwrap();
        value["country"] = serde_json::json!(7);
        assert!(
            serde_json::from_value::<CachedLocation>(value).is_err(),
            "a wrong-typed field must fail"
        );
    }

    /// The loader's own schema-version refusal. Root-gated like the
    /// strict-load happy path (the walk precedes the check).
    #[test]
    fn a_wrong_schema_version_fails_for_root_runners() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let cache = LocationCache::new(dir.path().join("location.json"));
        let mut wrong = doc();
        wrong.schema_version = 99;
        cache.store(&wrong).unwrap();
        let root_owned = std::fs::metadata(dir.path())
            .map(|m| m.uid() == 0 && m.gid() == 0)
            .unwrap_or(false);
        if !root_owned {
            eprintln!(
                "NOTICE: skipping a_wrong_schema_version_fails_for_root_runners: the \
                 ownership arm of the fs_trust walk is unprovable unprivileged"
            );
            return;
        }
        match cache.load_strict(dir.path()) {
            Err(LocationCacheError::Malformed(report)) => assert!(
                report.contains("schema"),
                "the schema mismatch must be named: {report}"
            ),
            other => panic!("a wrong schema version must fail: {other:?}"),
        }
    }

    /// The oversized-document cap refuses on store, BEFORE any I/O (a
    /// file the loader would reject must never be written — the
    /// catalog post-serialization precedent).
    #[test]
    fn the_size_cap_refuses_on_store() {
        let dir = tempfile::tempdir().unwrap();
        let cache = LocationCache::new(dir.path().join("location.json"));
        let mut oversized = doc();
        oversized.isp = "x".repeat(MAX_LOCATION_BYTES);
        match cache.store(&oversized) {
            Err(LocationCacheError::TooLarge(_)) => {}
            other => panic!("the oversized document must refuse to store: {other:?}"),
        }
        assert!(
            !cache.path().exists(),
            "the refused document must not be written"
        );
    }

    /// IP discipline on the persisted document: `Debug` never renders
    /// the IP or the ISP (the api-side model's rule, applied here too).
    #[test]
    fn the_cached_document_debug_never_renders_the_ip_or_isp() {
        let rendered = format!("{:?}", doc());
        assert!(!rendered.contains("192.0.2.1"), "the IP leaked: {rendered}");
        assert!(
            !rendered.contains("Synthetic Test ISP"),
            "the ISP leaked: {rendered}"
        );
        assert!(
            rendered.contains("[redacted]"),
            "the redaction marker: {rendered}"
        );
        assert!(
            rendered.contains("1771000000"),
            "the provenance renders: {rendered}"
        );
    }

    /// The strict loader refuses a world-writable leaf regardless of
    /// ownership (pass 1 of the walk runs before the ownership pass —
    /// the catalog's unprivileged-proof tamper arm).
    #[test]
    fn a_tampered_leaf_fails_the_strict_load() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let cache = LocationCache::new(dir.path().join("location.json"));
        cache.store(&doc()).unwrap();
        std::fs::set_permissions(cache.path(), std::fs::Permissions::from_mode(0o666)).unwrap();
        match cache.load_strict(dir.path()) {
            Err(LocationCacheError::FsTrust(_)) => {}
            other => panic!("a world-writable leaf must fail the walk: {other:?}"),
        }
    }
}
