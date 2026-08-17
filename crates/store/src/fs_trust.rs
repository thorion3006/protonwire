//! Strict-mode filesystem trust walk (round-8 X5, sshd `StrictModes`-style).
//!
//! The root daemon applies whatever document sits at the system config
//! path, so that path is a privilege-escalation surface: anyone able to
//! plant or replace the file — by owning it, sharing a group with write
//! access, or symlinking it — controls root-daemon policy. Before a
//! SYSTEM-authority document is read, every component of its path is
//! `lstat`-checked:
//!
//! * no component may be a symbolic link (each component is inspected
//!   with `lstat`, so a link is seen as a link, never followed);
//! * the leaf must be a regular file, every ancestor a directory;
//! * no component may grant group or world write permission;
//! * every component must be owned by root (uid 0 and gid 0).
//!
//! ## Walk rule
//!
//! The walk covers the leaf and every ancestor directory up to and
//! including a *trust root* — `/` for production callers, the sshd
//! `StrictModes` rule. `/etc` and every parent of `/etc/protonwire` is
//! root-owned 0755 on a real system, so walking to `/` adds no false
//! rejections there. A shallower trust root is an explicit opt-in for
//! hermetic tests, which construct the whole tree under the temp
//! directory that plays the root and trust everything above it by
//! construction; the walk never inspects anything above the trust root.
//!
//! The walk is lexical (no `canonicalize` — resolving symlinks would hide
//! the very links the walk exists to reject) and happens-before-use, so
//! like sshd's check it is not an atomic guarantee against a concurrent
//! swap; it closes the standing hole where a hostile file simply sits at
//! the path.
//!
//! ## Defect report order
//!
//! Checks run in two passes — symlink/type/mode first, ownership second —
//! each pass walking leaf-first. Every violation in either pass is a hard
//! rejection; the fixed order only makes the defect *named* in an error
//! deterministic, and keeps the mode and symlink arms constructible (and
//! assertable, down to the named defect) by unprivileged test runners,
//! who cannot `chown` their artifacts to root.
//!
//! Placement: the walker lives in `protonwire-store` beside the system
//! config loader that consumes it ([`crate::config`]); the runtime
//! directory pinning track item (`/run/protonwire`) is expected to reuse
//! it from here rather than grow a second walker.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The uid every strict-mode path component must be owned by.
pub const ROOT_UID: u32 = 0;
/// The gid every strict-mode path component must be owned by.
pub const ROOT_GID: u32 = 0;

/// Group and world write bits — either set on a component is a defect.
const WRITE_BEYOND_OWNER: u32 = 0o022;

/// How [`verify_trusted_path`] treats a missing leaf component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingLeaf {
    /// A missing leaf is a defect: the path must exist in full.
    Reject,
    /// A missing leaf is acceptable to the walk — every ancestor is still
    /// verified. Callers that treat absence as "use defaults" (the system
    /// config loader) reject a symlinked ancestor even when the leaf it
    /// points at is absent.
    Allow,
}

/// Walks `path` from its leaf up to and including `trust_root`, rejecting
/// any component that is a symlink, has the wrong type (leaf: regular
/// file; ancestors: directory), grants group/world write, or is not
/// owned by root. See the [module documentation](self) for the walk rule
/// and defect order.
pub fn verify_trusted_path(
    path: &Path,
    trust_root: &Path,
    missing_leaf: MissingLeaf,
) -> Result<(), FsTrustError> {
    let chain = component_chain(path, trust_root)?;
    // Pass 1: symlink, component type, and mode — leaf first, so the
    // defect nearest the document is the one named.
    let mut inspected: Vec<(&Path, Option<Metadata>)> = Vec::with_capacity(chain.len());
    for (index, component) in chain.iter().enumerate() {
        let meta = match std::fs::symlink_metadata(component) {
            Ok(meta) => Some(meta),
            Err(source)
                if source.kind() == std::io::ErrorKind::NotFound
                    && missing_leaf == MissingLeaf::Allow =>
            {
                // Absent-and-SKIP on ANY component (rust-review round 8,
                // live-reproduced against the daemon): a missing component
                // can carry no defect — not a symlink, no write bits — and
                // no leaf can exist beneath it, so the loader's subsequent
                // read NotFound selects the defaults path, which stays
                // safe. Ancestors that DO exist are still verified, so a
                // symlinked or writable ancestor cannot launder an
                // absence. Under MissingLeaf::Reject an absent leaf stays
                // the caller's hard error, and other inspection failures
                // stay hard (where "could not inspect" is accurate).
                None
            }
            Err(source) => {
                return Err(FsTrustError::Io {
                    path: (*component).to_path_buf(),
                    source,
                });
            }
        };
        if let Some(meta) = meta.as_ref() {
            if meta.file_type().is_symlink() {
                return Err(FsTrustError::Symlink {
                    path: (*component).to_path_buf(),
                });
            }
            if index == 0 {
                if !meta.is_file() {
                    return Err(FsTrustError::NotARegularFile {
                        path: (*component).to_path_buf(),
                    });
                }
            } else if !meta.is_dir() {
                return Err(FsTrustError::NotADirectory {
                    path: (*component).to_path_buf(),
                });
            }
            let mode = meta.mode() & 0o777;
            if mode & WRITE_BEYOND_OWNER != 0 {
                return Err(FsTrustError::GroupWorldWritable {
                    path: (*component).to_path_buf(),
                    mode,
                });
            }
        }
        inspected.push((component, meta));
    }
    // Pass 2: ownership. `filter` keeps the metadata only when it is the
    // defect — an owned-by-root component drops out, an absent leaf has
    // nothing to check here.
    for (component, meta) in inspected {
        if let Some(meta) = meta.filter(|meta| meta.uid() != ROOT_UID || meta.gid() != ROOT_GID) {
            return Err(FsTrustError::NotRootOwned {
                path: component.to_path_buf(),
                uid: meta.uid(),
                gid: meta.gid(),
            });
        }
    }
    Ok(())
}

/// The components of `path` from leaf to `trust_root` (inclusive), after
/// validating that both endpoints are absolute and that `path` actually
/// runs through `trust_root`.
fn component_chain<'a>(path: &'a Path, trust_root: &Path) -> Result<Vec<&'a Path>, FsTrustError> {
    if !path.is_absolute() {
        return Err(FsTrustError::NotAbsolute {
            path: path.to_path_buf(),
        });
    }
    if !trust_root.is_absolute() {
        return Err(FsTrustError::NotAbsolute {
            path: trust_root.to_path_buf(),
        });
    }
    let mut chain = Vec::new();
    for ancestor in path.ancestors() {
        chain.push(ancestor);
        if ancestor == trust_root {
            return Ok(chain);
        }
    }
    Err(FsTrustError::NotUnderTrustRoot {
        path: path.to_path_buf(),
        trust_root: trust_root.to_path_buf(),
    })
}

/// A strict-mode trust violation. Every variant names the offending path
/// component and the specific defect, so the surfaced error is directly
/// actionable (`chown root:root /etc/protonwire`, `chmod g-w ...`, remove
/// the link, ...).
#[derive(Debug, thiserror::Error)]
pub enum FsTrustError {
    /// The component is a symbolic link.
    #[error(
        "{path} is a symbolic link; strict-mode path components must be real files and directories, never links"
    )]
    Symlink {
        /// The offending component.
        path: PathBuf,
    },
    /// The component grants group or world write permission.
    #[error(
        "{path} has mode {mode:#o} granting group/world write; strict-mode path components must not be writable beyond their owner"
    )]
    GroupWorldWritable {
        /// The offending component.
        path: PathBuf,
        /// Its permission bits (masked to 0o777).
        mode: u32,
    },
    /// The component is not owned by root (uid 0 and gid 0).
    #[error(
        "{path} is owned by uid {uid} gid {gid}; strict-mode path components must be owned by root (uid 0, gid 0)"
    )]
    NotRootOwned {
        /// The offending component.
        path: PathBuf,
        /// Its owning uid.
        uid: u32,
        /// Its owning gid.
        gid: u32,
    },
    /// The leaf is not a regular file.
    #[error("{path} is not a regular file")]
    NotARegularFile {
        /// The offending component.
        path: PathBuf,
    },
    /// An ancestor is not a directory.
    #[error("{path} is not a directory")]
    NotADirectory {
        /// The offending component.
        path: PathBuf,
    },
    /// The path (or trust root) is not absolute.
    #[error("{path} must be an absolute path for the strict-mode trust walk")]
    NotAbsolute {
        /// The offending path.
        path: PathBuf,
    },
    /// The path never runs through the trust root.
    #[error("{path} is not under the trust root {trust_root}")]
    NotUnderTrustRoot {
        /// The path that is not under the root.
        path: PathBuf,
        /// The trust root it never reaches.
        trust_root: PathBuf,
    },
    /// A component could not be `lstat`-ed; if its trust cannot be
    /// established, it cannot be granted.
    #[error("could not inspect {path}: {source}")]
    Io {
        /// The component that could not be inspected.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt;

    /// A clean tree under `root/a/b` with a 0644 leaf; mode and symlink
    /// arms stay provable unprivileged because pass 1 runs before the
    /// ownership pass.
    fn clean_tree(root: &Path) -> PathBuf {
        let dir = root.join("a").join("b");
        std::fs::create_dir_all(&dir).unwrap();
        let leaf = dir.join("config.yaml");
        std::fs::write(&leaf, "schema_version: 2\n").unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644)).unwrap();
        leaf
    }

    /// The walk stops at the trust root: a defect ABOVE the root (the
    /// 0777 tempdir itself) must never be examined, while the same tree
    /// with the defect at the root is rejected. Root runners see the
    /// accept; unprivileged runners see the ownership pass trip — both
    /// prove the mode defect above the root was not reached.
    #[test]
    fn walk_stops_at_the_trust_root() {
        let root = tempfile::tempdir().unwrap();
        let leaf = clean_tree(root.path());
        let inner = root.path().join("a");

        match verify_trusted_path(&leaf, &inner, MissingLeaf::Reject) {
            Ok(()) => {} // running as root: full accept below the defect
            Err(FsTrustError::NotRootOwned { .. }) => {} // unprivileged: only pass 2 tripped
            Err(other) => panic!("walk must stop at the trust root: {other}"),
        }

        // Same tree, trust root at the defective directory: the mode
        // defect is now inside the walk and fires in pass 1.
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = verify_trusted_path(&leaf, root.path(), MissingLeaf::Reject).unwrap_err();
        assert!(
            matches!(err, FsTrustError::GroupWorldWritable { ref path, .. } if path == root.path()),
            "the trust root itself is walked: {err}"
        );
    }

    /// Relative paths and paths that never run through the trust root are
    /// rejected before anything is inspected.
    #[test]
    fn relative_paths_and_foreign_roots_rejected() {
        let root = tempfile::tempdir().unwrap();
        let leaf = clean_tree(root.path());
        let err = verify_trusted_path(
            Path::new("relative/config.yaml"),
            root.path(),
            MissingLeaf::Reject,
        )
        .unwrap_err();
        assert!(matches!(err, FsTrustError::NotAbsolute { .. }), "{err}");
        let err = verify_trusted_path(&leaf, Path::new("relative-root"), MissingLeaf::Reject)
            .unwrap_err();
        assert!(matches!(err, FsTrustError::NotAbsolute { .. }), "{err}");
        let foreign = root.path().join("elsewhere");
        let err = verify_trusted_path(&leaf, &foreign, MissingLeaf::Reject).unwrap_err();
        assert!(
            matches!(err, FsTrustError::NotUnderTrustRoot { .. }),
            "{err}"
        );
    }

    /// The missing-leaf policy: `Reject` reports the absent leaf as an
    /// inspection failure; `Allow` skips the leaf yet still walks every
    /// ancestor — so a symlinked ancestor cannot be laundered by removing
    /// the leaf it points at.
    #[test]
    fn missing_leaf_policy_walks_ancestors_either_way() {
        let root = tempfile::tempdir().unwrap();
        let leaf = clean_tree(root.path());
        std::fs::remove_file(&leaf).unwrap();

        let err = verify_trusted_path(&leaf, root.path(), MissingLeaf::Reject).unwrap_err();
        assert!(
            matches!(err, FsTrustError::Io { ref path, .. } if path == &leaf),
            "Reject must report the absent leaf: {err}"
        );
        match verify_trusted_path(&leaf, root.path(), MissingLeaf::Allow) {
            // Root runners own the whole tree as root:root, so the walk
            // passes and the caller decides absence. Unprivileged runners
            // cannot construct that, so the ownership pass trips instead
            // — either way the leaf was skipped (no Io error).
            Ok(()) | Err(FsTrustError::NotRootOwned { .. }) => {}
            Err(other) => panic!("Allow must skip the absent leaf: {other}"),
        }

        // A symlinked ancestor with no leaf through it still rejects.
        let real = root.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = root.path().join("a").join("b").join("c");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let via = link.join("config.yaml");
        let err = verify_trusted_path(&via, root.path(), MissingLeaf::Allow).unwrap_err();
        assert!(matches!(err, FsTrustError::Symlink { .. }), "{err}");
    }

    /// Pass-1 defects name the exact offending component: a symlinked
    /// leaf, a symlinked ancestor, a group-writable leaf, a
    /// world-writable ancestor, and a non-file leaf.
    #[test]
    fn pass_one_defects_name_the_offending_component() {
        let root = tempfile::tempdir().unwrap();

        let leaf = clean_tree(root.path());
        let real = leaf.with_file_name("real.yaml");
        std::fs::rename(&leaf, &real).unwrap();
        std::os::unix::fs::symlink(&real, &leaf).unwrap();
        let err = verify_trusted_path(&leaf, root.path(), MissingLeaf::Reject).unwrap_err();
        assert!(
            matches!(err, FsTrustError::Symlink { ref path } if path == &leaf),
            "{err}"
        );
        std::fs::remove_file(&leaf).unwrap();
        std::fs::rename(&real, &leaf).unwrap();

        let link_dir = root.path().join("linked");
        std::fs::create_dir_all(&link_dir).unwrap();
        // The leaf must exist through the link, so pass 1 reaches the
        // linked ancestor instead of stopping at a missing leaf.
        std::fs::write(link_dir.join("config.yaml"), "schema_version: 2\n").unwrap();
        let via_link = root.path().join("a/b/linked/config.yaml");
        std::os::unix::fs::symlink(&link_dir, root.path().join("a/b/linked")).unwrap();
        let err = verify_trusted_path(&via_link, root.path(), MissingLeaf::Reject).unwrap_err();
        assert!(
            matches!(err, FsTrustError::Symlink { ref path } if path.ends_with("a/b/linked")),
            "{err}"
        );

        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o664)).unwrap();
        let err = verify_trusted_path(&leaf, root.path(), MissingLeaf::Reject).unwrap_err();
        assert!(
            matches!(err, FsTrustError::GroupWorldWritable { ref path, mode } if path == &leaf && mode == 0o664),
            "{err}"
        );
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644)).unwrap();

        let ancestor = leaf.parent().unwrap();
        std::fs::set_permissions(ancestor, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = verify_trusted_path(&leaf, root.path(), MissingLeaf::Reject).unwrap_err();
        assert!(
            matches!(err, FsTrustError::GroupWorldWritable { ref path, .. } if path == ancestor),
            "{err}"
        );
        std::fs::set_permissions(ancestor, std::fs::Permissions::from_mode(0o755)).unwrap();

        // A directory where the document should be is a type defect.
        let dir_leaf = leaf.with_file_name("leafdir");
        std::fs::create_dir(&dir_leaf).unwrap();
        let err = verify_trusted_path(&dir_leaf, root.path(), MissingLeaf::Reject).unwrap_err();
        assert!(
            matches!(err, FsTrustError::NotARegularFile { ref path } if path == &dir_leaf),
            "{err}"
        );
    }
}
