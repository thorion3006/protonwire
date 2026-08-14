//! Canonical filesystem locations (PRD section 10).

use std::path::{Path, PathBuf};

/// Every path the daemon and clients use, overridable for tests and
/// development.
#[derive(Debug, Clone)]
pub struct ConfigPaths {
    /// Root-owned system configuration.
    pub system_config: PathBuf,
    /// Daemon runtime state (`state.json`).
    pub state_file: PathBuf,
    /// Cache directory (server catalog, latency results).
    pub cache_dir: PathBuf,
    /// IPC socket directory.
    pub socket_dir: PathBuf,
    /// IPC socket name.
    pub socket_name: String,
}

impl ConfigPaths {
    /// The production locations.
    pub fn system() -> Self {
        Self {
            system_config: PathBuf::from("/etc/protonwire/config.yaml"),
            state_file: PathBuf::from("/var/lib/protonwire/state.json"),
            cache_dir: PathBuf::from("/var/cache/protonwire"),
            socket_dir: PathBuf::from("/run/protonwire"),
            socket_name: "protonwire.sock".into(),
        }
    }

    /// Locations rooted under a single directory (tests, development).
    pub fn rooted(root: &Path) -> Self {
        Self {
            system_config: root.join("etc/protonwire/config.yaml"),
            state_file: root.join("var/lib/protonwire/state.json"),
            cache_dir: root.join("var/cache/protonwire"),
            socket_dir: root.join("run/protonwire"),
            socket_name: "protonwire.sock".into(),
        }
    }

    /// Full socket path.
    pub fn socket_path(&self) -> PathBuf {
        self.socket_dir.join(&self.socket_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_paths_match_prd() {
        let paths = ConfigPaths::system();
        assert_eq!(paths.system_config, Path::new("/etc/protonwire/config.yaml"));
        assert_eq!(paths.state_file, Path::new("/var/lib/protonwire/state.json"));
        assert_eq!(paths.cache_dir, Path::new("/var/cache/protonwire"));
        assert_eq!(
            paths.socket_path(),
            Path::new("/run/protonwire/protonwire.sock")
        );
    }
}
