//! `SO_PEERCRED` peer credential lookup, plus the strict-mode trust walk
//! the client applies to the daemon socket's path before connecting.
//!
//! ## The socket trust walk (M2 S12)
//!
//! The client-side check consolidates onto the semantics of the store
//! crate's `fs_trust` walker (round-8 X5, sshd `StrictModes`-style):
//! every component of the socket path from the leaf up to and including
//! a trust root is inspected with `lstat`-style metadata (a symlink is
//! seen as the link, never followed), no component may grant write
//! beyond its owner, and every component must be owned by root. The
//! pre-S12 check followed symlinks (`metadata`) and inspected a single
//! ancestor, so a lookalike link or a writable grandparent laundered the
//! path.
//!
//! WHY A DUPLICATE, NOT AN IMPORT: the dep-graph gate
//! (`xtask/src/deps.rs`) puts `protonwire-store` in `DEEP_DEPS` and
//! walks the RESOLVED graph from every client-side package —
//! `protonwire-client -> protonwire-ipc -> protonwire-store` is exactly
//! the "frontends reach the service only through protonwire-client"
//! route it exists to reject (T-23), so `protonwire-ipc` may not depend
//! on the crate that owns `crates/store/src/fs_trust.rs`. Moving the
//! walker to a legal shared home is not free either: the only crate
//! below both `store` and `ipc` is `protonwire-frontend-api`, whose
//! charter is wire types only. The walker is therefore duplicated here
//! WITH the store crate's walk rule as its specification (same walk,
//! same defect classes, same leaf-first two-pass order so unprivileged
//! runners can still observe pass-1 defects); when the two ever diverge,
//! that is a defect in this copy. Socket-leaf deltas from the fs_trust
//! rule, both forced by the R9-1 group hand-off (`bind.rs`: the socket
//! is deliberately `0o660 root:<client-group>`, and connect(2) needs
//! write permission on the socket inode):
//!
//! * the leaf must be a SOCKET (not a regular file);
//! * the leaf may grant GROUP write (the production shape 0o660) —
//!   world write is still rejected — and its gid is unconstrained (the
//!   chown hands the socket to the client group);
//! * directory components keep the full rule: no group/world write,
//!   owned by root's uid AND gid.
//!
//! Like sshd's check the walk is lexical and happens-before-use, so it
//! is not an atomic guarantee against a concurrent swap; the
//! kernel-captured `SO_PEERCRED` of the connected stream remains the
//! authoritative identity check (see `client.rs`).

use std::fs::Metadata;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use nix::sys::socket::{getsockopt, sockopt};

/// The uid every strict-mode socket-path component must be owned by.
const ROOT_UID: u32 = 0;
/// The gid every strict-mode socket-path DIRECTORY must be owned by (the
/// socket leaf's gid is the R9-1 group hand-off and is unconstrained).
const ROOT_GID: u32 = 0;

/// Group and world write bits — either set on a DIRECTORY component is a
/// defect (on the socket leaf only the world bit is; see the module doc).
const WRITE_BEYOND_OWNER: u32 = 0o022;
/// World write bit — the one forbidden even on the socket leaf, because a
/// world-writable socket is world-connectable.
const WORLD_WRITE: u32 = 0o002;

/// Credentials of the process on the other end of a Unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    /// Effective UID of the peer process.
    pub uid: u32,
    /// Effective GID of the peer process.
    pub gid: u32,
    /// PID of the peer process, when available.
    pub pid: Option<i32>,
}

impl PeerCredentials {
    /// Reads the peer credentials of a connected Unix stream socket.
    pub fn of(stream: &UnixStream) -> io::Result<Self> {
        let creds = getsockopt(stream, sockopt::PeerCredentials).map_err(io::Error::other)?;
        Ok(Self {
            uid: creds.uid(),
            gid: creds.gid(),
            // PID 0 means "not available" in the kernel ucred contract.
            pid: (creds.pid() > 0).then_some(creds.pid()),
        })
    }

    /// Whether the peer is the root user.
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }
}

/// Walks `socket` from its leaf up to and including `trust_root`,
/// rejecting any component that is a symlink, has the wrong type (leaf:
/// socket; ancestors: directory), grants write beyond its owner (leaf:
/// world write; ancestors: group or world write), or is not owned by
/// root (leaf: uid; ancestors: uid and gid). See the
/// [module documentation](self) for the walk rule, its socket-leaf
/// deltas from the store walker, and why the walker is duplicated here.
///
/// Production callers walk to `/` (the sshd `StrictModes` rule);
/// `trust_root` exists so the boundary itself is testable against
/// hermetic trees.
pub(crate) fn walk_socket_trust(socket: &Path, trust_root: &Path) -> Result<(), SocketTrustError> {
    let chain = component_chain(socket, trust_root)?;
    // Pass 1: symlink, component type, and mode — leaf first, so the
    // defect nearest the socket is the one named. Keeping pass 1 ahead
    // of the ownership pass (the store walker's order) is what lets an
    // unprivileged test runner observe and assert these defects: it
    // cannot chown its artifacts to root, but mode and symlink defects
    // fire before ownership ever runs.
    let mut inspected: Vec<(&Path, Metadata)> = Vec::with_capacity(chain.len());
    for (index, component) in chain.iter().enumerate() {
        let meta = std::fs::symlink_metadata(component).map_err(|source| SocketTrustError::Io {
            path: (*component).to_path_buf(),
            source,
        })?;
        if meta.file_type().is_symlink() {
            return Err(SocketTrustError::Symlink {
                path: (*component).to_path_buf(),
            });
        }
        let mode = meta.mode() & 0o777;
        if index == 0 {
            use std::os::unix::fs::FileTypeExt;
            if !meta.file_type().is_socket() {
                return Err(SocketTrustError::NotASocket {
                    path: (*component).to_path_buf(),
                });
            }
            if mode & WORLD_WRITE != 0 {
                return Err(SocketTrustError::WorldWritableSocket {
                    path: (*component).to_path_buf(),
                    mode,
                });
            }
        } else {
            if !meta.is_dir() {
                return Err(SocketTrustError::NotADirectory {
                    path: (*component).to_path_buf(),
                });
            }
            if mode & WRITE_BEYOND_OWNER != 0 {
                return Err(SocketTrustError::GroupWorldWritable {
                    path: (*component).to_path_buf(),
                    mode,
                });
            }
        }
        inspected.push((component, meta));
    }
    // Pass 2: ownership. The socket leaf needs only root UID — its gid
    // is the R9-1 client-group hand-off — while every directory needs
    // root's uid AND gid, exactly like the store walker.
    for (index, (component, meta)) in inspected.iter().enumerate() {
        let defective = if index == 0 {
            meta.uid() != ROOT_UID
        } else {
            meta.uid() != ROOT_UID || meta.gid() != ROOT_GID
        };
        if defective {
            return Err(SocketTrustError::NotRootOwned {
                path: (*component).to_path_buf(),
                uid: meta.uid(),
                gid: meta.gid(),
            });
        }
    }
    Ok(())
}

/// The components of `socket` from leaf to `trust_root` (inclusive),
/// after validating that both endpoints are absolute, that `socket` runs
/// through `trust_root`, and that `socket` carries no `.`/`..` component
/// (the walk is lexical, but the kernel would resolve those against the
/// live tree — the store walker's round-8 rule).
fn component_chain<'a>(
    socket: &'a Path,
    trust_root: &Path,
) -> Result<Vec<&'a Path>, SocketTrustError> {
    if !socket.is_absolute() {
        return Err(SocketTrustError::NotAbsolute {
            path: socket.to_path_buf(),
        });
    }
    if !trust_root.is_absolute() {
        return Err(SocketTrustError::NotAbsolute {
            path: trust_root.to_path_buf(),
        });
    }
    for component in socket.components() {
        if matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        ) {
            return Err(SocketTrustError::RelativeComponent {
                path: socket.to_path_buf(),
            });
        }
    }
    let mut chain = Vec::new();
    for ancestor in socket.ancestors() {
        chain.push(ancestor);
        if ancestor == trust_root {
            return Ok(chain);
        }
    }
    Err(SocketTrustError::NotUnderTrustRoot {
        path: socket.to_path_buf(),
        trust_root: trust_root.to_path_buf(),
    })
}

/// A strict-mode socket-trust violation. Every variant names the
/// offending path component and the specific defect, so the surfaced
/// error is directly actionable (`chown root:root /run/protonwire`,
/// `chmod g-w ...`, remove the link, ...).
#[derive(Debug, thiserror::Error)]
pub(crate) enum SocketTrustError {
    /// The component is a symbolic link.
    #[error(
        "{path} is a symbolic link; every component of the daemon socket's path must be a real file or directory, never a link"
    )]
    Symlink {
        /// The offending component.
        path: PathBuf,
    },
    /// The leaf is not a socket.
    #[error("{path} is not a socket")]
    NotASocket {
        /// The offending component.
        path: PathBuf,
    },
    /// The socket leaf grants world write permission — world-connectable.
    #[error(
        "{path} has mode {mode:#o} granting world write; a world-writable socket is world-connectable"
    )]
    WorldWritableSocket {
        /// The offending component.
        path: PathBuf,
        /// Its permission bits (masked to 0o777).
        mode: u32,
    },
    /// A directory component grants group or world write permission.
    #[error(
        "{path} has mode {mode:#o} granting group/world write; every directory on the daemon socket's path must not be writable beyond its owner"
    )]
    GroupWorldWritable {
        /// The offending component.
        path: PathBuf,
        /// Its permission bits (masked to 0o777).
        mode: u32,
    },
    /// The component is not owned by root (directories: uid 0 and gid 0;
    /// the socket leaf: uid 0 — its gid is the R9-1 client-group
    /// hand-off).
    #[error(
        "{path} is owned by uid {uid} gid {gid}; the daemon socket's path must be root-owned (uid 0; gid 0 for directories)"
    )]
    NotRootOwned {
        /// The offending component.
        path: PathBuf,
        /// Its owning uid.
        uid: u32,
        /// Its owning gid.
        gid: u32,
    },
    /// An ancestor is not a directory.
    #[error("{path} is not a directory")]
    NotADirectory {
        /// The offending component.
        path: PathBuf,
    },
    /// The socket (or trust root) is not absolute.
    #[error("{path} must be an absolute path for the strict-mode socket trust walk")]
    NotAbsolute {
        /// The offending path.
        path: PathBuf,
    },
    /// The socket path contains a `.` or `..` component; the kernel
    /// would resolve it against the live tree, escaping the walk.
    #[error(
        "{path} contains a `.` or `..` component; the daemon socket's path must be normalized and absolute"
    )]
    RelativeComponent {
        /// The rejected path.
        path: PathBuf,
    },
    /// The socket path never runs through the trust root.
    #[error("{path} is not under the trust root {trust_root}")]
    NotUnderTrustRoot {
        /// The path that is not under the root.
        path: PathBuf,
        /// The trust root it never reaches.
        trust_root: PathBuf,
    },
    /// A component could not be `lstat`-ed; trust that cannot be
    /// established cannot be granted.
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

    #[test]
    fn peer_credentials_of_socketpair() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let creds = PeerCredentials::of(&a).unwrap();
        assert_eq!(creds.uid, nix::unistd::getuid().as_raw());
        let _ = b;
    }

    mod trust_walk {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        /// A clean tree under `root/a/b` with a bound socket leaf, all
        /// at ordinary user modes/ownership. Pass-1 defects (symlink,
        /// type, mode) fire before the ownership pass, so unprivileged
        /// runners can construct and assert them; the ownership pass
        /// itself trips NotRootOwned for such trees unless the runner IS
        /// root.
        fn socket_tree(root: &Path) -> PathBuf {
            let dir = root.join("a").join("b");
            std::fs::create_dir_all(&dir).unwrap();
            let leaf = dir.join("protonwire.sock");
            drop(std::os::unix::net::UnixListener::bind(&leaf).unwrap());
            leaf
        }

        /// The walk stops at the trust root (the store walker's boundary
        /// rule, mirrored): a defect ABOVE the root must never be
        /// examined, while the same defect AT the root fires. Root
        /// runners see the below-root accept; unprivileged runners see
        /// the ownership pass trip — both prove the defect above the
        /// root was not reached, because with the root as the trust root
        /// the mode defect fires in pass 1 before ownership could.
        #[test]
        fn walk_stops_at_the_trust_root() {
            let root = tempfile::tempdir().unwrap();
            let leaf = socket_tree(root.path());
            let inner = root.path().join("a");

            // The tempdir itself is the defect (world-writable below).
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
            match walk_socket_trust(&leaf, &inner) {
                Ok(()) => {} // running as root: full accept below the defect
                Err(SocketTrustError::NotRootOwned { .. }) => {} // unprivileged
                Err(other) => panic!("walk must stop at the trust root: {other}"),
            }

            // Same tree, trust root AT the defective directory: the mode
            // defect is inside the walk and fires in pass 1 — proof the
            // boundary moved, not that the walk got looser.
            let err = walk_socket_trust(&leaf, root.path()).unwrap_err();
            assert!(
                matches!(err, SocketTrustError::GroupWorldWritable { ref path, .. } if path == root.path()),
                "the trust root itself is walked: {err}"
            );
        }

        /// A symlinked ANCESTOR launders nothing: the walk inspects the
        /// link, names the link. (The symlinked LEAF case is pinned at
        /// the client seam in `client.rs`; this is the deeper component.)
        #[test]
        fn symlinked_ancestor_is_rejected_naming_the_link() {
            let root = tempfile::tempdir().unwrap();
            let real = root.path().join("real");
            std::fs::create_dir_all(&real).unwrap();
            drop(std::os::unix::net::UnixListener::bind(real.join("s.sock")).unwrap());
            std::fs::create_dir_all(root.path().join("a").join("b")).unwrap();
            std::os::unix::fs::symlink(&real, root.path().join("a").join("b").join("linked"))
                .unwrap();
            let via = root.path().join("a/b/linked/s.sock");

            let err = walk_socket_trust(&via, root.path()).unwrap_err();
            assert!(
                matches!(err, SocketTrustError::Symlink { ref path } if path.ends_with("a/b/linked")),
                "a symlinked ancestor must be named: {err}"
            );
        }

        /// The leaf type check: anything but a socket at the leaf is a
        /// defect, even a regular file a client could mistake for one.
        #[test]
        fn non_socket_leaf_is_rejected() {
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join("a").join("b");
            std::fs::create_dir_all(&dir).unwrap();
            let leaf = dir.join("protonwire.sock");
            std::fs::write(&leaf, b"not a socket").unwrap();

            let err = walk_socket_trust(&leaf, root.path()).unwrap_err();
            assert!(
                matches!(err, SocketTrustError::NotASocket { ref path } if *path == leaf),
                "a regular file at the socket leaf must be named: {err}"
            );
        }

        /// Path-shape rejections fire before any inspection (the store
        /// walker's rules): relative paths, foreign trust roots, and
        /// `.`/`..` components.
        #[test]
        fn path_shape_defects_are_rejected_before_inspection() {
            let root = tempfile::tempdir().unwrap();
            let leaf = socket_tree(root.path());
            let err = walk_socket_trusted_shape_check(Path::new("relative.sock"), root.path());
            assert!(matches!(err, SocketTrustError::NotAbsolute { .. }), "{err}");
            let err = walk_socket_trusted_shape_check(&leaf, Path::new("relative-root"));
            assert!(matches!(err, SocketTrustError::NotAbsolute { .. }), "{err}");
            let foreign = root.path().join("elsewhere");
            let err = walk_socket_trusted_shape_check(&leaf, &foreign);
            assert!(
                matches!(err, SocketTrustError::NotUnderTrustRoot { .. }),
                "{err}"
            );
            let dotted = Path::new("/run/../protonwire/s.sock");
            let err = walk_socket_trusted_shape_check(dotted, Path::new("/"));
            assert!(
                matches!(err, SocketTrustError::RelativeComponent { .. }),
                "{err}"
            );
        }

        fn walk_socket_trusted_shape_check(socket: &Path, trust_root: &Path) -> SocketTrustError {
            // Drive only the chain builder through the public walk: the
            // shape defects below return before any component is
            // inspected, so no fixture tree is needed for them.
            match walk_socket_trust(socket, trust_root) {
                Err(e) => e,
                Ok(()) => panic!("{socket:?} against {trust_root:?} must be rejected"),
            }
        }

        /// Ownership: an unprivileged runner's tree is user-owned and
        /// the walk names uid/gid (root runners own their artifacts as
        /// root:root and see the full accept — both arms prove the pass
        /// runs). Group-write on the LEAF stays legal (the R9-1 0o660
        /// shape) while the same mode on a DIRECTORY is a pass-1 defect.
        #[test]
        fn ownership_pass_names_the_component_and_leaf_group_write_is_legal() {
            let root = tempfile::tempdir().unwrap();
            let leaf = socket_tree(root.path());
            // The production leaf shape: 0o660.
            std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o660)).unwrap();

            match walk_socket_trust(&leaf, root.path()) {
                Ok(()) => {} // root runner: root-owned 0o660 leaf accepted
                Err(SocketTrustError::NotRootOwned { uid, gid, .. }) => {
                    assert_eq!(uid, nix::unistd::getuid().as_raw());
                    assert_eq!(gid, nix::unistd::getgid().as_raw());
                }
                Err(other) => panic!(
                    "a 0o660 leaf must trip only the ownership pass for a \
                     non-root runner: {other}"
                ),
            }

            // The same group-write bits on the parent DIRECTORY are a
            // pass-1 defect. 0o770, not 0o660: a directory without an
            // execute bit for its owner is not even traversable, so the
            // leaf's lstat would fail with EACCES instead of the mode
            // defect being named — and the tempdir could not clean up
            // after itself either.
            let parent = leaf.parent().unwrap();
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o770)).unwrap();
            let err = walk_socket_trust(&leaf, root.path()).unwrap_err();
            assert!(
                matches!(err, SocketTrustError::GroupWorldWritable { ref path, .. } if path == parent),
                "group write on a directory component must fire in pass 1: {err}"
            );
        }

        /// ROOT-gated arm (skip FIRST on `!getuid().is_root()`, the
        /// standing rule): as root, a clean tree passes the whole walk,
        /// and the pre-S12 red's exact shape — a SYMLINK at the socket
        /// path inside an otherwise clean root-owned tree, which the
        /// old `metadata`-following check ACCEPTED — is rejected. The
        /// unprivileged suite cannot construct this (its artifacts are
        /// user-owned, so the old check rejected them on ownership
        /// before the follow ever mattered); the pre-fix acceptance is
        /// inspection-level evidence: `std::fs::metadata` resolves the
        /// link, and a socket target in a root-owned 0755 tree passed
        /// every check the old code had.
        #[test]
        fn as_root_a_clean_tree_passes_and_a_symlinked_leaf_is_rejected() {
            if !nix::unistd::getuid().is_root() {
                eprintln!(
                    "NOTICE: skipping as_root_a_clean_tree_passes_and_a_symlinked_leaf_is_rejected: \
                     not running as root — the full-accept and symlink-accept arms \
                     need a root-owned tree"
                );
                return;
            }
            let root = tempfile::tempdir().unwrap();
            let leaf = socket_tree(root.path());
            for dir in [
                root.path(),
                &root.path().join("a"),
                &root.path().join("a/b"),
            ] {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o660)).unwrap();
            walk_socket_trust(&leaf, root.path())
                .expect("a clean root-owned tree with a 0o660 socket passes the walk");

            // The symlinked leaf: clean tree, link standing where the
            // socket should be. Pre-S12 this was ACCEPTED (the reason
            // the consolidation exists).
            let target = leaf.with_file_name("real.sock");
            std::fs::rename(&leaf, &target).unwrap();
            std::os::unix::fs::symlink(&target, &leaf).unwrap();
            let err = walk_socket_trust(&leaf, root.path()).unwrap_err();
            assert!(
                matches!(err, SocketTrustError::Symlink { ref path } if *path == leaf),
                "a symlink at the socket leaf must be rejected even as root: {err}"
            );
        }
    }
}
