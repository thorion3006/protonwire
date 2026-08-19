//! The bind path of [`IpcServer`]: socket-directory setup, the entry
//! guards at the bind path (live-daemon refusal, stale-socket policy,
//! the symlink matrix), the 0o660 mode, and the root-gated
//! client-group chown (R9-1).

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use tracing::{debug, info};

use crate::server::IpcServer;

impl IpcServer {
    /// Binds `socket_dir/socket_name`.
    ///
    /// Creates the directory if missing, refuses to displace a live daemon's
    /// socket, removes a stale socket file left by an unclean shutdown, and
    /// refuses loudly to remove any NON-socket entry at the path (a regular
    /// file there also answers ECONNREFUSED on the liveness probe — the
    /// probe alone must never authorize the unlink). The socket is created
    /// with mode `0o660`. See
    /// [`IpcServer::bind_with_group`] for the client-group chown a root
    /// daemon needs on top of that mode.
    pub fn bind(socket_dir: &Path, socket_name: &str) -> io::Result<Self> {
        Self::bind_with_group(socket_dir, socket_name, None)
    }

    /// [`IpcServer::bind`] with the socket additionally chowned to `group`.
    ///
    /// PRD 6.3: a root daemon creates the socket root:root, and the 0o660
    /// mode alone then admits no unprivileged client. With a group
    /// configured the socket is chowned to that group's gid (owner
    /// untouched) right after the mode is applied, so members of the group
    /// can connect. An unresolvable group name fails loudly — a daemon
    /// started with a typo'd group is a daemon nobody can reach.
    ///
    /// R9-1: the whole group hand-off (resolution AND chown) is gated on
    /// the daemon running as root. The configuration default is now
    /// `Some("protonwire")` — the group the shipped package provisions —
    /// and an unprivileged dev launch on a box without that group would
    /// otherwise fail the lookup loudly (or the chown with EPERM): a
    /// default must not brick non-root dev, so non-root keeps today's
    /// no-chown behavior. The missing-group fail-loud contract is
    /// therefore a ROOT-daemon contract, and the group's existence is the
    /// M8 packaging dependency (the package creates the `protonwire`
    /// group).
    pub fn bind_with_group(
        socket_dir: &Path,
        socket_name: &str,
        group: Option<&str>,
    ) -> io::Result<Self> {
        Self::bind_with_resolved(
            socket_dir,
            socket_name,
            group,
            &process_is_root,
            &resolve_group_gid,
            &chown_socket_group,
            &bind_socket_staged,
        )
    }

    /// The bind path with the root gate, group resolver, chown, and
    /// listener factory ALL injectable (tests pin the hand-off between
    /// them — root gate open: resolver output to chown input, exactly
    /// once, with the bound path; root gate closed: neither half runs —
    /// without a group database or root; the listener factory is the
    /// staging bind ([`bind_socket_staged`]) — injectable so a test can
    /// wrap or replace the publish step itself; production goes through
    /// [`IpcServer::bind_with_group`]).
    #[allow(clippy::too_many_arguments)]
    fn bind_with_resolved(
        socket_dir: &Path,
        socket_name: &str,
        group: Option<&str>,
        is_root: &dyn Fn() -> bool,
        resolver: &dyn Fn(&str) -> io::Result<Option<nix::unistd::Gid>>,
        chown: &dyn Fn(&Path, &str, nix::unistd::Gid) -> io::Result<()>,
        bind_listener: &dyn Fn(&Path, &Path) -> io::Result<UnixListener>,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(socket_dir)?;
        pin_runtime_dir(socket_dir)?;
        let socket_path = socket_dir.join(socket_name);
        // FU-B (round-6 residual): `Path::exists()` follows links, so a
        // DANGLING symlink at the bind path read as "the name is free"
        // and bind(2) then failed with an opaque EADDRINUSE. Existence is
        // judged on the dirent itself — any entry reaches the guard below,
        // which names it; a NotFound is the only "free" answer; every
        // other stat error propagates.
        match std::fs::symlink_metadata(&socket_path) {
            Ok(_) => {
                refuse_unless_stale_socket(&socket_path)?;
                std::fs::remove_file(&socket_path)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = bind_listener(socket_dir, &socket_path)?;
        // Idempotent re-pin of the published socket (the staging factory
        // already applied 0o660 BEFORE publishing; this also covers
        // injected factories that do not).
        set_socket_mode(&socket_path)?;
        if let Some(name) = group {
            // R9-1: the hand-off is a root-daemon contract. Non-root keeps
            // today's no-chown behavior so the `Some("protonwire")` default
            // cannot brick a dev launch (unprovisioned group → fail-loud
            // lookup; foreign gid → EPERM). Skipped loudly enough to debug:
            // a debug record, not a refusal.
            if !is_root() {
                debug!(
                    group = name,
                    "not running as root; skipping the socket group chown"
                );
            } else {
                let gid = resolver(name)?.ok_or_else(|| {
                    io::Error::other(format!("socket group `{name}` does not exist"))
                })?;
                chown(&socket_path, name, gid)?;
                // sec-auditor round-9 verdict (R9-1 Low): operators must
                // be able to audit WHAT was granted — AnyUser covers
                // Connect/Disconnect, so the resolved gid earns a line.
                info!(
                    group = name,
                    gid = gid.as_raw(),
                    "socket chowned to the configured client group"
                );
            }
        }
        info!(path = %socket_path.display(), "IPC server bound");
        Ok(Self {
            listener,
            socket_path,
        })
    }
}

/// Whether a connect failure definitively identifies a stale socket file
/// and therefore authorizes removing it (Codex PR review finding 11).
///
/// `ECONNREFUSED` is the only such signal: a stream socket with no
/// listener refuses immediately. Every other failure (descriptor
/// exhaustion, `EACCES`, ...) is inconclusive — the socket may belong to
/// a live but unreachable daemon — and must abort startup instead of
/// unlinking it and letting a second daemon bind the same path.
fn authorizes_unlink(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::ConnectionRefused
}

/// Refuses to remove a socket another daemon is actively serving.
fn ensure_not_live(socket_path: &Path) -> io::Result<()> {
    // Local Unix sockets connect immediately; only a REFUSED connect
    // proves no live listener owns the path. Inconclusive errors are
    // returned so `bind` fails loudly instead of unlinking.
    match UnixStream::connect(socket_path) {
        Ok(_) => Err(io::Error::other(format!(
            "another daemon is serving {}",
            socket_path.display()
        ))),
        Err(e) if authorizes_unlink(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Authorizes removing the entry at `socket_path` only if it is a SOCKET
/// that no live daemon is serving (pr-champion round 6, WO-W1; FU-B).
///
/// The liveness probe alone cannot carry this: connect(2) to ANY non-socket
/// path — a regular file above all — answers ECONNREFUSED, the exact signal
/// [`authorizes_unlink`] treats as proof of staleness. Ungated, that let
/// bind remove the user's file and bind over the crater. The entry's TYPE
/// is therefore checked first (and the probe never even runs against a
/// non-socket), and any non-socket entry aborts bind loudly, naming the
/// path and what it actually is.
///
/// The entry is judged through `symlink_metadata`, so a SYMLINK at the bind
/// path is the link: refusals name the link (or, when it resolves to
/// nothing, the dangling link), while the staleness probe follows it — a
/// link to a stale socket authorizes removing the LINK, and the file it
/// points at survives untouched.
fn refuse_unless_stale_socket(socket_path: &Path) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let meta = std::fs::symlink_metadata(socket_path)?;
    let file_type = meta.file_type();
    if file_type.is_socket() {
        return ensure_not_live(socket_path);
    }
    if file_type.is_symlink() {
        // Judge the LINK for the refusal, its TARGET for the probe: only a
        // link resolving to a socket can authorize an unlink, and the
        // probe then follows the link exactly as a connecting client
        // would. Any other resolution (a regular file above all, or
        // nothing at all) refuses naming the link; a target that cannot
        // even be stat'ed (ELOOP, EACCES) propagates loudly.
        return match std::fs::metadata(socket_path) {
            Ok(target) if target.file_type().is_socket() => ensure_not_live(socket_path),
            Ok(_) => Err(not_a_socket(socket_path, "symlink")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Err(not_a_socket(socket_path, "dangling symlink"))
            }
            Err(e) => Err(e),
        };
    }
    Err(not_a_socket(socket_path, entry_kind(&meta)))
}

/// The bind refusal for a non-socket entry: loud, and naming both the path
/// and what actually sits there.
fn not_a_socket(socket_path: &Path, kind: &str) -> io::Error {
    io::Error::other(format!(
        "refusing to remove {}: not a socket ({kind})",
        socket_path.display()
    ))
}

/// Human name for an entry's file type, used to say WHAT bind refused to
/// remove. Callers feed it `symlink_metadata` output, so a link is
/// reported as the LINK itself — the `is_symlink` arm is reachable only
/// through lstat-style metadata.
fn entry_kind(meta: &std::fs::Metadata) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    let file_type = meta.file_type();
    if file_type.is_file() {
        "regular file"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_fifo() {
        "FIFO"
    } else if file_type.is_char_device() {
        "character device"
    } else if file_type.is_block_device() {
        "block device"
    } else {
        "unknown entry type"
    }
}

fn set_socket_mode(socket_path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))
}

/// Pins the runtime directory to mode `0o755` and fail-loud VERIFIES the
/// pin held (M2 S12; round-4 track item (b), sharpened by the round-6
/// sec item): `create_dir_all` inherits the process umask, so umask-0077
/// produced a 0700 runtime dir — no traversal, defeating the R9-1 group
/// hand-off for every member client — while umask-000 (or an operator's
/// hand-made dir) shipped 0777, a planting surface for lookalike
/// sockets. 0755 is the recorded contract: root:root-owned (the daemon's
/// own chown discipline), traversable by everyone, writable by no one
/// but root.
fn pin_runtime_dir(socket_dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o755)).map_err(|e| {
        io::Error::other(format!(
            "cannot pin the runtime directory {} to 0755: {e}",
            socket_dir.display()
        ))
    })?;
    // Fail-loud verify: whatever the filesystem, a concurrent chmod, or a
    // stale mount did, a runtime dir that is not exactly 0755 must abort
    // startup rather than serve from an unverified mode.
    let mode = std::fs::metadata(socket_dir)
        .map_err(|e| {
            io::Error::other(format!(
                "cannot verify the runtime directory {}: {e}",
                socket_dir.display()
            ))
        })?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o755 {
        return Err(io::Error::other(format!(
            "runtime directory {} has mode {mode:#o} after the 0755 pin; refusing to serve",
            socket_dir.display()
        )));
    }
    Ok(())
}

/// Counter making each staging directory unique within a process (two
/// concurrent binds in the same socket dir must not share one).
static STAGING_SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The production listener factory (M2 S12; round-4 track item (a)):
/// closes the bind-then-chmod window STRUCTURALLY. Sockets are born
/// `0777 & ~umask`, so a plain bind at the public path left the socket
/// world-CONNECTABLE for the moment before `set_socket_mode`'s 0o660
/// chmod landed (connect(2) needs write permission on the socket
/// inode). Instead the socket is born inside an owner-only staging
/// directory — invisible and unreachable to any other uid — pinned to
/// 0o660, and only then published under its final name with `link(2)`:
/// the public name comes into existence exactly once, atomically,
/// already 0o660, and never REPLACES anything (EEXIST fails loud, the
/// same liveness discipline as the stale-socket guards above).
///
/// Why not the recorded `umask(2)` guard: umask is PROCESS-GLOBAL. The
/// guard was implemented first and its red/green observed, but its live
/// `0o117` window is inherited by EVERY concurrent file creation in the
/// process — reproduced in this suite, where parallel tests' temp
/// directories came out `0660` (no execute bit, EACCES storms, ~5% of
/// runs; guard windows averaged 76 µs across ~30 binds per run). The
/// daemon is multithreaded too; any startup-time creation racing the
/// bind would inherit the same mask, and no lock can help (the racing
/// creations do not cooperate). The staging shape carries no global
/// state at all.
fn bind_socket_staged(socket_dir: &Path, socket_path: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    let serial = STAGING_SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let staging = socket_dir.join(format!(".stage.{serial}.{}", socket_name_of(socket_path)));
    // A crashed predecessor's staging dir must not wedge this bind; it
    // held nothing public, so removing it is safe.
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir(&staging)?;
    if let Err(e) = std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }
    let staged_socket = staging.join("s.sock");
    let listener = match UnixListener::bind(&staged_socket) {
        Ok(listener) => listener,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
    };
    // Mode FIRST, publish second: whatever mode the kernel gave the
    // staged inode (umask-dependent), the public name only ever meets
    // the pinned 0o660 one.
    if let Err(e) = set_socket_mode(&staged_socket) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }
    // link(2), not rename(2): rename would silently REPLACE an entry
    // that appeared at the public name since the guards above ran —
    // stealing a live daemon's socket. link fails EEXIST instead, the
    // fail-loud answer bind(2) itself would have given.
    if let Err(e) = std::fs::hard_link(&staged_socket, socket_path) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(io::Error::other(format!(
            "cannot publish the staged socket at {}: {e} (another daemon may \
             have bound it during startup)",
            socket_path.display()
        )));
    }
    // The staged name can go: the public hard link keeps the inode.
    let _ = std::fs::remove_file(&staged_socket);
    let _ = std::fs::remove_dir(&staging);
    Ok(listener)
}

/// The file-name component of the staged socket's final path (staging
/// names are per-target so concurrent binds to different sockets in one
/// directory cannot collide even before the serial disambiguates).
fn socket_name_of(socket_path: &Path) -> String {
    socket_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sock")
        .to_owned()
}

/// Whether this daemon runs as root — the gate for the socket-group
/// hand-off (R9-1; see [`IpcServer::bind_with_group`]). Injected through
/// [`IpcServer::bind_with_resolved`] so the gate itself is testable
/// without a privileged runner.
fn process_is_root() -> bool {
    nix::unistd::getuid().is_root()
}

/// Resolves a group name to its gid through the system group database.
fn resolve_group_gid(name: &str) -> io::Result<Option<nix::unistd::Gid>> {
    nix::unistd::Group::from_name(name)
        .map(|group| group.map(|g| g.gid))
        .map_err(|e| io::Error::other(format!("cannot look up group `{name}`: {e}")))
}

/// Chowns the bound socket to `gid`, leaving its owner alone.
fn chown_socket_group(socket_path: &Path, name: &str, gid: nix::unistd::Gid) -> io::Result<()> {
    nix::unistd::chown(socket_path, None, Some(gid))
        .map_err(|e| io::Error::other(format!("cannot chown socket to group `{name}`: {e}")))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

    use super::*;

    /// Codex PR review finding 11 (P2): only a definitive stale-socket
    /// signal (ECONNREFUSED) may authorize unlinking the socket file. Any
    /// other connect failure (descriptor exhaustion, EACCES, ...) is
    /// inconclusive: unlinking then leaves a live daemon unreachable while
    /// another instance binds the same path.
    #[test]
    fn only_connection_refused_authorizes_unlinking_a_stale_socket() {
        use std::os::unix::fs::PermissionsExt;

        // A stale socket (listener dropped, file left behind) is removable.
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("stale.sock");
        let listener = std::os::unix::net::UnixListener::bind(&stale).unwrap();
        drop(listener);
        assert!(authorizes_unlink(&connect_error(&stale)));

        // An inconclusive failure (EACCES with the parent dir closed to us;
        // meaningful only for non-root test users) must NOT authorize it.
        if !nix::unistd::getuid().is_root() {
            let closed = dir.path().join("closed");
            std::fs::create_dir(&closed).unwrap();
            let socket = closed.join("s.sock");
            let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
            let verdict = authorizes_unlink(&connect_error(&socket));
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
            drop(listener);
            assert!(
                !verdict,
                "EACCES is inconclusive and must abort startup, not unlink"
            );
        }
    }

    /// End-to-end bind behavior for the two clear outcomes.
    #[test]
    fn bind_refuses_live_and_replaces_stale_sockets() {
        let dir = tempfile::tempdir().unwrap();
        // Stale: listener gone, file remains.
        let stale_dir = dir.path().join("a");
        std::fs::create_dir(&stale_dir).unwrap();
        drop(std::os::unix::net::UnixListener::bind(stale_dir.join("s.sock")).unwrap());
        assert!(IpcServer::bind(&stale_dir, "s.sock").is_ok());
        // Live: a serving listener owns the path.
        let live_dir = dir.path().join("b");
        std::fs::create_dir(&live_dir).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(live_dir.join("s.sock")).unwrap();
        let err = IpcServer::bind(&live_dir, "s.sock")
            .map(|_| ())
            .expect_err("live socket must abort bind");
        assert!(
            err.to_string().contains("another daemon"),
            "live socket must abort bind, got: {err}"
        );
        drop(listener);
    }

    /// S12 item 2 (round-4 track item (b), sharpened by the round-6 sec
    /// item): `create_dir_all` inherits the process umask, so a
    /// umask-0077 daemon produced a 0700 runtime dir — no traversal, and
    /// the R9-1 group hand-off was defeated for every member client.
    /// bind must PIN the runtime dir to 0755 (root:root traversal without
    /// plantability) whatever the umask left behind. Pre-fix red: the
    /// pre-created 0700 dir survived bind untouched.
    #[test]
    fn bind_widens_an_over_tight_runtime_dir_to_0755() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let server = IpcServer::bind(&runtime, "s.sock").unwrap();
        let mode = std::fs::metadata(server.socket_path().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "the runtime dir must be pinned to 0755");
    }

    /// S12 item 2, the other direction: a permissive runtime dir
    /// (umask-000, or an operator hand-making it) is a planting surface
    /// for lookalike sockets — the strict client walk rejects it, but
    /// bind must not ship it in the first place. The pin TIGHTENS too.
    /// Pre-fix red: the 0777 dir survived bind untouched.
    #[test]
    fn bind_tightens_a_permissive_runtime_dir_to_0755() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o777)).unwrap();
        let server = IpcServer::bind(&runtime, "s.sock").unwrap();
        let mode = std::fs::metadata(server.socket_path().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "the runtime dir must be pinned to 0755");
    }

    /// S12 item 2 (round-4 track item (a)): the pre-existing
    /// bind-then-chmod window. Sockets are born `0777 & ~umask`, so under
    /// a permissive umask a plain bind at the public path left the socket
    /// world-CONNECTABLE for the moment before the 0o660 chmod landed
    /// (connect(2) needs write permission on the socket inode). The
    /// staging factory closes the window STRUCTURALLY: the socket is born
    /// inside an owner-only directory, pinned to 0o660, and only then
    /// published by an atomic `link(2)`.
    ///
    /// Red evidence (observed while developing, recorded here): with the
    /// ambient umask at 0o000 and the socket bound plainly at the public
    /// path, the observed creation mode was 0o777 (511) — the recorded
    /// umask-guard variant was green against exactly that. The pin below
    /// is the property the window violated, observed from OUTSIDE: a
    /// poller stats the public path continuously while the main thread
    /// rebinds in a loop, and EVERY observation of an existing entry must
    /// report 0o660. The green is deterministic (a link(2) publish is
    /// atomic); a plain-bind mutation reintroduces the window and fails
    /// this on the first observed 0777/0755.
    #[test]
    fn bind_publishes_the_socket_only_at_its_final_mode() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::AtomicBool;

        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();
        let public = runtime.join("s.sock");

        let polling = Arc::new(AtomicBool::new(true));
        let observed: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let poller = {
            let polling = Arc::clone(&polling);
            let observed = Arc::clone(&observed);
            let public = public.clone();
            std::thread::spawn(move || {
                while polling.load(Ordering::SeqCst) {
                    if let Ok(meta) = std::fs::symlink_metadata(&public) {
                        observed
                            .lock()
                            .unwrap()
                            .push(meta.permissions().mode() & 0o777);
                    }
                }
            })
        };

        for _ in 0..50 {
            let server = IpcServer::bind_with_resolved(
                &runtime,
                "s.sock",
                None,
                &|| false,
                &|_name| panic!("no group configured: the resolver must not run"),
                &|_path, _name, _gid| panic!("no group configured: the chown must not run"),
                &bind_socket_staged,
            )
            .unwrap();
            drop(server); // Drop removes the public name; the loop rebinds.
        }
        polling.store(false, Ordering::SeqCst);
        let _ = poller.join();

        let observed = observed.lock().unwrap().clone();
        assert!(
            !observed.is_empty(),
            "the poller never saw the public name — vacuous pass"
        );
        let odd = observed
            .iter()
            .filter(|mode| **mode != 0o660)
            .copied()
            .collect::<Vec<_>>();
        assert!(
            odd.is_empty(),
            "the public socket was observable at {odd:?} — every existing \
             observation must already be the published 0o660 mode"
        );
    }

    /// S12 item 2, staging hygiene: a successful bind leaves no staging
    /// litter in the runtime dir, and the publish step stays fail-loud —
    /// a name taken between the stale-socket guards and the `link(2)`
    /// (simulated here by the factory planting the entry itself) refuses
    /// naming the collision instead of silently replacing it, and even
    /// the FAILED publish cleans its staging directory up.
    #[test]
    fn staged_publish_is_fail_loud_on_a_taken_name_and_leaves_no_litter() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        std::fs::create_dir_all(&runtime).unwrap();

        let server = IpcServer::bind(&runtime, "s.sock").unwrap();
        let entries: Vec<String> = std::fs::read_dir(&runtime)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries,
            vec!["s.sock".to_owned()],
            "a successful bind must leave only the published socket — no \
             staging litter: {entries:?}"
        );
        let mode = std::fs::metadata(server.socket_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o660);
        drop(server);

        // The publish arm: the public name is TAKEN after the guards ran
        // (the injected factory plants it, then delegates to the real
        // staging bind — link(2) must refuse, not replace).
        let squatter = runtime.join("s.sock");
        let planting = |_dir: &Path, path: &Path| -> io::Result<UnixListener> {
            std::fs::write(&squatter, b"squatted after the guards").unwrap();
            bind_socket_staged(_dir, path)
        };
        let err = IpcServer::bind_with_resolved(
            &runtime,
            "s.sock",
            None,
            &|| false,
            &|_name| panic!("no group configured: the resolver must not run"),
            &|_path, _name, _gid| panic!("no group configured: the chown must not run"),
            &planting,
        )
        .map(|_| ())
        .expect_err("a name taken between the guards and the link must refuse");
        assert!(
            err.to_string().contains("cannot publish"),
            "the refusal must name the failed publish, got: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&squatter).unwrap(),
            "squatted after the guards",
            "the refusal must not have replaced the taken name"
        );
        let entries: Vec<String> = std::fs::read_dir(&runtime)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries,
            vec!["s.sock".to_owned()],
            "even a failed publish must clean its staging directory up: {entries:?}"
        );
    }

    /// pr-champion round 6, WO-W1: a REGULAR file at the socket path also
    /// answers ECONNREFUSED on the liveness probe (connect(2) to any
    /// non-socket refuses), so `authorizes_unlink` alone passed and
    /// `remove_file` destroyed the user's file before binding over it. The
    /// entry's TYPE must authorize the unlink: anything but a socket aborts
    /// bind loudly, naming the path and the actual entry type, and the
    /// file's contents survive untouched. A stale SOCKET keeps the existing
    /// replace-and-bind behavior.
    #[test]
    fn bind_refuses_to_unlink_non_socket_entries() {
        let dir = tempfile::tempdir().unwrap();

        // A regular file at the bind path: refuse loudly, name the type,
        // leave the contents intact.
        let file_dir = dir.path().join("regular");
        std::fs::create_dir(&file_dir).unwrap();
        let hoarded = file_dir.join("s.sock");
        std::fs::write(&hoarded, "precious data").unwrap();
        let err = IpcServer::bind(&file_dir, "s.sock")
            .map(|_| ())
            .expect_err("a regular file at the bind path must abort bind");
        assert!(
            err.to_string().contains("refusing to remove"),
            "the refusal must be explicit, got: {err}"
        );
        assert!(
            err.to_string().contains("regular file"),
            "the refusal must name the entry type, got: {err}"
        );
        assert!(
            err.to_string().contains("s.sock"),
            "the refusal must name the path, got: {err}"
        );
        assert!(
            hoarded.is_file(),
            "the entry itself must survive the refusal"
        );
        assert_eq!(
            std::fs::read_to_string(&hoarded).unwrap(),
            "precious data",
            "bind must not destroy the file's contents"
        );

        // A directory at the bind path: refused too (remove_file on a
        // directory only fails with EISDIR — an opaque error that names
        // neither the refusal nor the type).
        let dir_case = dir.path().join("dircase");
        std::fs::create_dir(&dir_case).unwrap();
        let as_socket = dir_case.join("s.sock");
        std::fs::create_dir(&as_socket).unwrap();
        let err = IpcServer::bind(&dir_case, "s.sock")
            .map(|_| ())
            .expect_err("a directory at the bind path must abort bind");
        assert!(
            err.to_string().contains("refusing to remove"),
            "directories are refused like any non-socket, got: {err}"
        );
        assert!(
            err.to_string().contains("directory"),
            "the refusal must name the entry type, got: {err}"
        );
        assert!(as_socket.is_dir(), "the directory must survive");

        // A stale socket (listener dropped, file left behind) is still
        // replaced and bound — existing behavior pinned.
        let stale_dir = dir.path().join("stale");
        std::fs::create_dir(&stale_dir).unwrap();
        drop(std::os::unix::net::UnixListener::bind(stale_dir.join("s.sock")).unwrap());
        let server = IpcServer::bind(&stale_dir, "s.sock")
            .expect("a stale socket at the bind path is still replaced");
        assert!(
            server.socket_path().exists(),
            "the replacement socket must be bound"
        );
    }

    /// FU-B (round-6 residual): nothing pinned symlink behavior at the
    /// bind path. `Path::exists()` FOLLOWS links, so a DANGLING symlink
    /// answered "nothing there" and bind(2) then failed with an opaque
    /// EADDRINUSE — while the guard's `metadata` judged whatever a link
    /// RESOLVED to, never the link itself. The link cases below pin the
    /// matrix alongside the direct ones above: a link to a stale socket is
    /// replaced like a stale socket (the LINK goes, the target survives),
    /// and a link to a live daemon is refused fail-closed.
    #[test]
    fn bind_replaces_a_symlink_to_a_stale_socket_leaving_the_target_untouched() {
        use std::os::unix::fs::FileTypeExt;
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let case = dir.path().join("stale-link");
        std::fs::create_dir(&case).unwrap();
        // The stale socket lives at another name; s.sock is a symlink to it.
        let target = case.join("real.sock");
        drop(std::os::unix::net::UnixListener::bind(&target).unwrap());
        symlink(&target, case.join("s.sock")).unwrap();

        let server = IpcServer::bind(&case, "s.sock")
            .expect("a link to a stale socket is replaced like a stale socket");
        // The LINK was removed and a real socket bound in its place...
        assert!(
            std::fs::symlink_metadata(server.socket_path())
                .expect("the bound entry exists")
                .file_type()
                .is_socket(),
            "the bind path must now be the daemon's own socket, not a link"
        );
        // ...while the file it pointed at survived untouched.
        assert!(
            std::fs::symlink_metadata(&target)
                .expect("the link's target survives")
                .file_type()
                .is_socket(),
            "replacing the link must not remove the socket file it pointed at"
        );

        // The live arm of the matrix: a link to a LIVE daemon's socket is
        // refused (the probe follows the link), and neither the link nor
        // the listener is disturbed.
        let live = dir.path().join("live-link");
        std::fs::create_dir(&live).unwrap();
        let live_target = live.join("real.sock");
        let listener = std::os::unix::net::UnixListener::bind(&live_target).unwrap();
        symlink(&live_target, live.join("s.sock")).unwrap();
        let err = IpcServer::bind(&live, "s.sock")
            .map(|_| ())
            .expect_err("a link to a live daemon's socket must abort bind");
        assert!(
            err.to_string().contains("another daemon"),
            "the liveness probe must follow the link and refuse, got: {err}"
        );
        assert!(
            std::fs::symlink_metadata(live.join("s.sock"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the refused link must survive"
        );
        drop(listener);
    }

    /// FU-B: a symlink to a REGULAR file is refused naming the LINK — the
    /// entry at the bind path is the symlink, and saying "regular file"
    /// (what the link resolves to) hides the surprising shape an
    /// administrator actually needs to go look at. The link and its target
    /// both survive.
    #[test]
    fn bind_refuses_a_symlink_to_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let case = dir.path().join("regular-link");
        std::fs::create_dir(&case).unwrap();
        let target = case.join("precious.txt");
        std::fs::write(&target, "precious data").unwrap();
        std::os::unix::fs::symlink(&target, case.join("s.sock")).unwrap();

        let err = IpcServer::bind(&case, "s.sock")
            .map(|_| ())
            .expect_err("a symlink at the bind path must abort bind");
        assert!(
            err.to_string().contains("refusing to remove"),
            "the refusal must be explicit, got: {err}"
        );
        assert!(
            err.to_string().contains("symlink"),
            "the refusal must name the entry itself — the symlink — not what \
             it resolves to, got: {err}"
        );
        assert!(
            std::fs::symlink_metadata(case.join("s.sock"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link must survive the refusal"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "precious data",
            "bind must not touch the link's target"
        );
    }

    /// FU-B: the dangling link — the case that sailed PAST the guard
    /// pre-fix. `exists()` follows links, so a link resolving to nothing
    /// read as "the path is free" and `UnixListener::bind` then failed
    /// with bind(2)'s opaque EADDRINUSE (a dirent occupies the name), an
    /// error that names neither the refusal nor the cause. The guard must
    /// see the dirent itself and refuse loudly.
    #[test]
    fn bind_names_a_dangling_symlink_instead_of_an_opaque_addrinuse() {
        let dir = tempfile::tempdir().unwrap();
        let case = dir.path().join("dangling");
        std::fs::create_dir(&case).unwrap();
        // Points at a name that has never existed.
        std::os::unix::fs::symlink(case.join("nothing.sock"), case.join("s.sock")).unwrap();

        let err = IpcServer::bind(&case, "s.sock")
            .map(|_| ())
            .expect_err("a dangling symlink at the bind path must abort bind");
        assert!(
            err.to_string().contains("refusing to remove"),
            "the refusal must be named — not bind(2)'s opaque EADDRINUSE, got: {err}"
        );
        assert!(
            err.to_string().contains("dangling symlink"),
            "the refusal must say the link resolves to nothing, got: {err}"
        );
        assert!(
            std::fs::symlink_metadata(case.join("s.sock"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the dangling link must survive the refusal"
        );
    }

    /// pr-champion WO-7 (PRD 6.3) + R9-1's root gate, through the
    /// production path: a ROOT daemon asked for an unresolvable group must
    /// fail loudly (a typo'd group is a daemon nobody can reach), while a
    /// NON-root daemon (dev) skips the whole hand-off — the
    /// `Some("protonwire")` default would otherwise brick every dev launch
    /// on a box without the packaged group. The group the package
    /// provisions IS the M8 packaging dependency: the unit that ships the
    /// daemon creates the `protonwire` group.
    #[test]
    fn bind_with_group_fails_loud_on_an_unknown_group_only_when_root() {
        let dir = tempfile::tempdir().unwrap();
        let group = Some("protonwire-no-such-group-3f9a");
        if nix::unistd::getuid().is_root() {
            let err = IpcServer::bind_with_group(dir.path(), "nope.sock", group)
                .map(|_| ())
                .expect_err("a root daemon with an unresolvable group must abort bind");
            assert!(
                err.to_string().contains("does not exist"),
                "fail-loud error must name the problem, got: {err}"
            );
        } else {
            let server = IpcServer::bind_with_group(dir.path(), "nope.sock", group)
                .expect("a non-root daemon must skip the group hand-off, not fail");
            assert!(
                server.socket_path().exists(),
                "the non-root bind must produce a usable socket"
            );
        }
    }

    /// A resolver failure (group database unreadable, say) maps to an
    /// io::Error instead of a panic or a silent skip.
    #[test]
    fn bind_with_group_maps_resolver_failures() {
        let dir = tempfile::tempdir().unwrap();
        let err = IpcServer::bind_with_resolved(
            dir.path(),
            "boom.sock",
            Some("clients"),
            &|| true, // root gate open: the resolver failure must surface
            &|_name| Err(io::Error::other("group database on fire")),
            &|_path, _name, _gid| panic!("resolution failed first: the chown must not run"),
            &bind_socket_staged,
        )
        .map(|_| ())
        .expect_err("a resolver failure must abort bind");
        assert!(
            err.to_string().contains("group database on fire"),
            "got: {err}"
        );
    }

    /// The second group-lookup error text (alongside the resolver-Err test
    /// above): a name that resolves to nothing must fail loudly naming the
    /// group — a daemon started with a typo'd group is a daemon nobody can
    /// reach.
    #[test]
    fn unresolved_group_names_fail_loud_through_the_seam() {
        let dir = tempfile::tempdir().unwrap();
        let err = IpcServer::bind_with_resolved(
            dir.path(),
            "missing.sock",
            Some("wheel-clients"),
            &|| true, // root gate open: the unresolved name must fail loudly
            &|_name| Ok(None),
            &|_path, _name, _gid| panic!("no gid was resolved: the chown must not run"),
            &bind_socket_staged,
        )
        .map(|_| ())
        .expect_err("an unresolvable group must abort bind");
        assert!(
            err.to_string().contains("does not exist"),
            "the lookup-failure text must say so, got: {err}"
        );
        assert!(
            err.to_string().contains("wheel-clients"),
            "the lookup-failure text must name the group, got: {err}"
        );
    }

    /// Without a configured group nothing is resolved or chowned: the
    /// socket keeps the process group and the 0o660 mode.
    #[test]
    fn bind_without_a_group_never_resolves_or_chowns() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let server = IpcServer::bind_with_resolved(
            dir.path(),
            "plain.sock",
            None,
            // Root gate OPEN: with no group configured nothing may run even
            // for root — the group check gates before the root check.
            &|| true,
            &|_| panic!("no group configured: the resolver must not run"),
            &|_path, _name, _gid| panic!("no group configured: the chown must not run"),
            &bind_socket_staged,
        )
        .unwrap();
        let meta = std::fs::metadata(server.socket_path()).unwrap();
        assert_eq!(meta.gid(), nix::unistd::getgid().as_raw());
        assert_eq!(meta.mode() & 0o777, 0o660);
    }

    /// The effectiveness pin for the chown (qa mutation gap), extended by
    /// R9-1 with the root gate: the whole group hand-off — resolution AND
    /// chown — must run ONLY for a root daemon. A non-root daemon (dev
    /// runs, this suite) keeps today's no-chown behavior, because the new
    /// `Some("protonwire")` default would otherwise brick every non-root
    /// launch: the packaged group does not exist on a dev box (fail-loud
    /// resolution) and a foreign-gid chown answers EPERM. The root arm
    /// still pins the hand-off itself: the chown seam fires EXACTLY ONCE
    /// per configured group, with the bound socket's path, the configured
    /// group name, and the gid the RESOLVER returned. The old
    /// `bind_with_group_applies_the_resolved_gid` pin was tautological (a
    /// fresh socket's gid already equals the process egid); recording the
    /// calls makes the delete-chown mutation fail here.
    #[test]
    fn chown_seam_gates_on_root_and_hands_off_the_resolved_gid() {
        // (Mutex comes from the module-level `use std::sync::{Arc, Mutex};`
        // — the local re-import shadowed it; rust-review nit.)
        let dir = tempfile::tempdir().unwrap();

        // NON-root arm: neither half of the hand-off may run. A default
        // group must not brick non-root dev, so the gate sits BEFORE the
        // resolver (an unprovisioned dev box would otherwise fail the
        // lookup loudly) as well as before the chown (EPERM).
        let resolved: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let chowned: Mutex<Vec<(PathBuf, String, u32)>> = Mutex::new(Vec::new());
        let server = IpcServer::bind_with_resolved(
            dir.path(),
            "seam-nonroot.sock",
            Some("protonwire"),
            &|| false,
            &|name| {
                resolved.lock().unwrap().push(name.to_owned());
                Ok(Some(nix::unistd::Gid::from_raw(12345)))
            },
            &|path, name, gid| {
                chowned
                    .lock()
                    .unwrap()
                    .push((path.to_owned(), name.to_owned(), gid.as_raw()));
                Ok(())
            },
            &bind_socket_staged,
        )
        .unwrap();
        assert!(
            server.socket_path().exists(),
            "non-root bind succeeds without the group hand-off"
        );
        assert!(
            resolved.lock().unwrap().is_empty(),
            "a non-root daemon must not even resolve the group — an \
             unprovisioned dev box would fail the lookup and brick the launch"
        );
        assert!(
            chowned.lock().unwrap().is_empty(),
            "a non-root daemon must not attempt the chown (EPERM)"
        );

        // ROOT arm: the full hand-off runs, exactly once, with the
        // resolver's gid — the delete-chown mutation fails here.
        let calls: Mutex<Vec<(PathBuf, String, u32)>> = Mutex::new(Vec::new());
        let server = IpcServer::bind_with_resolved(
            dir.path(),
            "seam.sock",
            Some("wheel-clients"),
            &|| true,
            // A gid this process does NOT hold: the seam runs unprivileged
            // precisely because the real chown never happens.
            &|_name| Ok(Some(nix::unistd::Gid::from_raw(12345))),
            &|path, name, gid| {
                calls
                    .lock()
                    .unwrap()
                    .push((path.to_owned(), name.to_owned(), gid.as_raw()));
                Ok(())
            },
            &bind_socket_staged,
        )
        .unwrap();
        let recorded = calls.lock().unwrap();
        assert_eq!(
            recorded.len(),
            1,
            "the chown seam must be invoked exactly once for the configured group"
        );
        let (path, name, gid) = &recorded[0];
        assert_eq!(
            path,
            server.socket_path(),
            "the chown must target the bound socket"
        );
        assert_eq!(name, "wheel-clients");
        assert_eq!(*gid, 12345, "the chown must receive the resolver's gid");
    }

    /// A chown failure (EPERM, say) passes through and aborts bind with
    /// the group still named — never swallowed into a daemon nobody can
    /// reach.
    #[test]
    fn chown_failures_pass_through_and_name_the_group() {
        let dir = tempfile::tempdir().unwrap();
        let err = IpcServer::bind_with_resolved(
            dir.path(),
            "chown-boom.sock",
            Some("wheel-clients"),
            &|| true, // root gate open: the chown failure must pass through
            &|_name| Ok(Some(nix::unistd::Gid::from_raw(12345))),
            &|_path, name, _gid| {
                Err(io::Error::other(format!(
                    "cannot chown socket to group `{name}`: permission denied"
                )))
            },
            &bind_socket_staged,
        )
        .map(|_| ())
        .expect_err("a chown failure must abort bind");
        assert!(
            err.to_string().contains("wheel-clients"),
            "the chown error must pass through naming the group, got: {err}"
        );
        assert!(
            err.to_string().contains("permission denied"),
            "the chown error must survive propagation un-mangled, got: {err}"
        );
    }

    /// Real-syscall smoke test for the unprivileged chgrp path: POSIX lets
    /// any user chgrp a file it owns to a group it belongs to, so
    /// resolving to the process's own gid exercises the real chown(2)
    /// alongside the 0o660 mode.
    ///
    /// Honest scope: this does NOT pin the chown call — a fresh socket's
    /// gid already equals the process egid, so these asserts stay green
    /// with the chown deleted (qa mutation evidence). The effectiveness
    /// pin is [`chown_seam_receives_the_resolved_gid`]; this test still
    /// proves the real syscall succeeds where POSIX allows it unprivileged
    /// and leaves the mode intact. (Environments inside a restricted user
    /// namespace where supplementary gids are unmapped still admit the
    /// primary gid; a FOREIGN group is the root-gated test below.)
    #[test]
    fn bind_with_group_applies_the_resolved_gid() {
        use std::os::unix::fs::MetadataExt;

        let gid = nix::unistd::getgid();
        let dir = tempfile::tempdir().unwrap();
        let server = IpcServer::bind_with_resolved(
            dir.path(),
            "grouped.sock",
            Some("clients"),
            &|| true, // root gate open: the real chgrp path runs
            &|_| Ok(Some(gid)),
            &chown_socket_group,
            &bind_socket_staged,
        )
        .unwrap();
        let meta = std::fs::metadata(server.socket_path()).unwrap();
        assert_eq!(meta.gid(), gid.as_raw());
        assert_eq!(meta.mode() & 0o777, 0o660);
    }

    /// Root-gated integration (mirroring the root-gated arm of
    /// `only_connection_refused_authorizes_unlinking_a_stale_socket`):
    /// only root may chown to a group it does not belong to, so the full
    /// production path — real resolver against the group database, real
    /// chown — runs when the suite executes as root outside a user
    /// namespace. Inside a user namespace (/proc/self/ns/user differing
    /// from /proc/1/ns/user — or pid 1's file being unstatable, the form
    /// this host exhibits) the process holds no mapping for foreign gids
    /// and chown(2) to them answers EINVAL, so that environment skips
    /// with a NOTICE rather than failing on the kernel's terms.
    #[test]
    fn bind_with_group_chowns_to_a_real_group_when_root() {
        use std::os::unix::fs::MetadataExt;

        // Skip-FIRST: non-root before the user-namespace gate (rust-review
        // keep-id repro). Under `unshare --user --map-current-user --fork
        // --pid --mount-proc` the pid-namespace init shares our user
        // namespace, so in_a_user_namespace() sees identical namespace
        // links and answers false — gating on it first made a plain
        // non-root run fall through to a "the gate is broken" panic. The
        // foreign-group chown needs root regardless of namespaces, so a
        // non-root run simply skips. (A rootful-CI canary assert needs an
        // explicit env var — review-log track item, not built here.)
        if !nix::unistd::getuid().is_root() {
            eprintln!(
                "NOTICE: skipping bind_with_group_chowns_to_a_real_group_when_root: \
                 not running as root — the foreign-group chown arm needs root"
            );
            return;
        }
        if in_a_user_namespace() {
            eprintln!(
                "NOTICE: skipping bind_with_group_chowns_to_a_real_group_when_root: the \
                 suite runs in a user namespace (/proc/self/ns/user differs from \
                 /proc/1/ns/user) where chown to a foreign gid answers EINVAL"
            );
            return;
        }
        let group = nix::unistd::Group::from_name("nogroup")
            .expect("nogroup resolves")
            .expect("nogroup exists");
        let dir = tempfile::tempdir().unwrap();
        let server = IpcServer::bind_with_group(dir.path(), "clients.sock", Some("nogroup"))
            .expect("root binds with a real group");
        let meta = std::fs::metadata(server.socket_path()).unwrap();
        assert_eq!(
            meta.gid(),
            group.gid.as_raw(),
            "socket must be chowned to the configured group"
        );
        assert_eq!(meta.mode() & 0o777, 0o660);
    }

    fn connect_error(path: &Path) -> io::Error {
        UnixStream::connect(path).expect_err("connect against a socket file must fail or succeed")
    }

    /// Whether the test process runs in a DIFFERENT user namespace than
    /// init (pid 1). Namespace files live on nsfs, one stable inode per
    /// namespace, so equal (dev, ino) means the same namespace. A process
    /// in a user namespace typically cannot even stat pid 1's file (its
    /// owner is unmapped there — exactly this host's quirk), which is
    /// just as decisive: the real-chown arm may run only where the init
    /// user namespace is positively confirmed. In such namespaces the
    /// process holds no mapping for foreign gids and chown(2) to them
    /// answers EINVAL — not a code fault, so that environment skips with
    /// a NOTICE rather than failing on the kernel's terms.
    fn in_a_user_namespace() -> bool {
        use std::os::unix::fs::MetadataExt;

        match (
            std::fs::metadata("/proc/1/ns/user"),
            std::fs::metadata("/proc/self/ns/user"),
        ) {
            (Ok(init), Ok(current)) => (init.dev(), init.ino()) != (current.dev(), current.ino()),
            // Unstatable /proc (or absent pid 1) cannot confirm the init
            // user namespace; assume the guarded case.
            _ => true,
        }
    }
}
