//! Daemon runtime state (`/var/lib/protonwire/state.json`) with atomic
//! persistence (PRD section 10).

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::yaml::MAX_YAML_BYTES;

/// Size ceiling for the state document (mirrors the YAML cap; the state is
/// JSON but bounded identically).
pub const MAX_STATE_BYTES: usize = MAX_YAML_BYTES;

/// The persisted daemon state document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StateFile {
    /// Schema version of the state document.
    pub schema_version: u32,
    /// The owner of the active or most recent connection attempt, if any.
    pub active_owner: Option<OwnerRecord>,
}

/// Who owns the active connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerRecord {
    /// Unix UID of the owner.
    pub uid: u32,
    /// When ownership was claimed (seconds since the Unix epoch).
    pub since_unix: u64,
}

/// Failures of the state store.
#[derive(Debug, thiserror::Error)]
pub enum StateStoreError {
    /// Reading or writing failed.
    #[error("state store I/O failure: {0}")]
    Io(#[from] io::Error),
    /// The document failed validation.
    #[error("invalid state document: {0}")]
    Parse(String),
}

/// Atomic read/modify/write access to the state file.
#[derive(Debug, Clone)]
pub struct StateStore {
    path: PathBuf,
}

impl StateStore {
    /// Opens (without creating) the store at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The state file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads the state document; a missing file is a default document.
    pub fn load(&self) -> Result<StateFile, StateStoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(StateFile::default()),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() > MAX_STATE_BYTES {
            return Err(StateStoreError::Parse(
                "state document exceeds size cap".into(),
            ));
        }
        serde_json::from_slice(&bytes).map_err(|e| StateStoreError::Parse(e.to_string()))
    }

    /// Persists the document atomically: write a sibling temp file, fsync,
    /// rename over the target.
    pub fn save(&self, state: &StateFile) -> Result<(), StateStoreError> {
        let bytes =
            serde_json::to_vec_pretty(state).map_err(|e| StateStoreError::Parse(e.to_string()))?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(StateStoreError::Parse(
                "state document exceeds size cap".into(),
            ));
        }
        let parent = self.path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let tmp = parent.join(format!(
            ".{}.tmp-{}",
            self.path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("state"),
            std::process::id()
        ));
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_loads_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path().join("state.json"));
        assert_eq!(store.load().unwrap().schema_version, 0);
        assert!(store.load().unwrap().active_owner.is_none());
    }

    #[test]
    fn save_is_atomic_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path().join("nested/state.json"));
        let state = StateFile {
            schema_version: 1,
            active_owner: Some(OwnerRecord {
                uid: 1000,
                since_unix: 1770000000,
            }),
        };
        store.save(&state).unwrap();
        assert_eq!(store.load().unwrap().schema_version, 1);
        assert_eq!(store.load().unwrap().active_owner.unwrap().uid, 1000);
        // No temp file left behind.
        let entries = std::fs::read_dir(dir.path().join("nested"))
            .unwrap()
            .count();
        assert_eq!(entries, 1);
    }

    #[test]
    fn corrupted_document_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(StateStore::new(&path).load().is_err());
    }
}
