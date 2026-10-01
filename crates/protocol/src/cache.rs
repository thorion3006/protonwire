//! The encrypted three-value persistent cache (M4 PR-2) — protun's
//! `PersistentCache` over root-owned files, ciphertext-only at rest.
//!
//! The key-source decision (the owner's call, 2026-09-17): **(a) a
//! root-owned random keyfile** `/var/lib/protonwire/cache.key`, mode
//! 0600, generated on first use — the master key for an AEAD over
//! each cache file. The AEAD is **XChaCha20-Poly1305** via the
//! `chacha20poly1305` crate — the SAME authenticated cipher the
//! tunnel's own data plane uses (boringtun), already in the build
//! graph via protun → pvpnclient → proton-boringtun (lock-verified:
//! zero new code); its 24-byte nonce makes RANDOM nonces safe
//! without a counter (no birthday concern at cache-write rates).
//!
//! File format (per cache key, under the cache dir, 0600):
//! `magic[7] || version[1] || nonce[24] || ciphertext[..]` — the
//! plaintext (certificate, private key, session) NEVER touches disk.
//! Every trace/log of this module carries only the cache KEY NAME,
//! never bytes (FR-7P/T-32; the disk-scan canary pins it).
//!
//! Blocking budget: protun calls these methods on its connection
//! thread — each is one small file read/write, bounded by the size
//! cap below, no network, no unbounded allocation.

use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use protun::api::connection::{CacheKey, PersistentCache};
use zeroize::Zeroizing;

/// File-format magic: "PWCACHE" + version 1.
const MAGIC: &[u8; 7] = b"PWCACHE";
const VERSION: u8 = 1;
/// XChaCha20's nonce size.
const NONCE_LEN: usize = 24;
/// The master key length (XChaCha20-Poly1305).
const KEY_LEN: usize = 32;
/// One cache file's hard cap (the values are certificates and keys —
/// tens of KB at most; a larger file is corruption, refused).
const MAX_FILE_LEN: u64 = 64 * 1024;
/// The maximum PLAINTEXT the cache accepts: the FILE cap minus the
/// complete serialization overhead — magic (7) + version (1) +
/// nonce (24) + Poly1305 tag (16) = 48 bytes (the bot round-5 P2:
/// a 65,489..=65,536-byte plaintext passed the old plaintext cap,
/// encrypted, then the FILE check rejected the +48 result — the
/// facade accepted what persistence would drop; the value
/// disappeared after restart). Both layers use THIS bound so the
/// facade's refusal and the write's are the same line.
pub(crate) const MAX_PLAINTEXT_LEN: usize =
    MAX_FILE_LEN as usize - MAGIC.len() - 1 - NONCE_LEN - 16;

/// The encrypted cache: one directory, one master keyfile.
///
/// Construct via [`EncryptedCache::open`] (production: creates the
/// keyfile with 0600 on first use — the daemon runs root-owned per
/// the trust model) or [`EncryptedCache::with_key_bytes`] (tests and
/// explicit key management).
pub struct EncryptedCache {
    dir: PathBuf,
    cipher: XChaCha20Poly1305,
}

impl std::fmt::Debug for EncryptedCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No key material, no path-derived secrets; the dir is the
        // daemon's own configured state path (public to the reader).
        formatter
            .debug_struct("EncryptedCache")
            .field("dir", &self.dir)
            .field("cipher", &"XChaCha20-Poly1305")
            .finish()
    }
}

impl EncryptedCache {
    /// Opens (or initializes) the cache at `dir`: loads the master
    /// key from `key_path`, creating it with fresh OS randomness and
    /// mode 0600 when absent (decision (a) — the root-owned keyfile).
    ///
    /// # Errors
    /// [`CacheError`] on I/O failure or a keyfile of the wrong size
    /// (a truncated/tampered keyfile refuses rather than re-keying —
    /// re-keying would silently orphan every existing cache file).
    pub fn open(dir: &Path, key_path: &Path) -> Result<Self, CacheError> {
        // Every intermediate holding key bytes is Zeroizing (the
        // gate review's P2): the read Vec, the fresh array, and the
        // to_vec copy all zeroize on EVERY drop path — early
        // returns included.
        let key: Zeroizing<Vec<u8>> = match read_keyfile(key_path)? {
            Some(bytes) => Zeroizing::new(bytes),
            None => {
                // First-use creation, SERIALIZED (the bot round-1
                // P2): the final path is created with NO-REPLACE
                // semantics — a racing initializer that loses reads
                // the WINNER's key back, never orphans its own.
                // The keyfile's PARENT is created first (the bot
                // round-11 P2): a natural first-run call
                // (`open(&state_dir, &state_dir.join("cache.key"))`)
                // has a missing state dir — read_keyfile read that
                // NotFound as "absent", and publishing into the
                // still-missing parent would fail ENOENT before the
                // with_key_bytes step that creates `dir` is reached.
                if let Some(parent) = key_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)
                        .map_err(|error| CacheError::KeyFile(format!("keyfile parent: {error}")))?;
                }
                let mut fresh = Zeroizing::new([0u8; KEY_LEN]);
                getrandom::fill(fresh.as_mut_slice())
                    .map_err(|error| CacheError::KeyFile(format!("OS randomness: {error}")))?;
                let mut nonce = [0u8; NONCE_LEN];
                getrandom::fill(&mut nonce)
                    .map_err(|error| CacheError::KeyFile(format!("OS randomness: {error}")))?;
                match create_keyfile_no_replace(key_path, fresh.as_slice(), &nonce) {
                    Ok(()) => Zeroizing::new(fresh.to_vec()),
                    Err(CreateKeyfileError::LostRace) => {
                        // Another initializer won: reload its key.
                        let winner = read_keyfile(key_path)?.ok_or_else(|| {
                            CacheError::KeyFile(
                                "the winning keyfile vanished mid-race — retry".to_owned(),
                            )
                        })?;
                        Zeroizing::new(winner)
                    }
                    Err(CreateKeyfileError::Io(error)) => return Err(error),
                }
            }
        };
        Self::with_key_bytes(dir, key.as_slice())
    }

    /// Opens the cache with an explicit master key (tests; explicit
    /// key-management lanes). The internal copy zeroizes on every
    /// drop path (the gate review's doc correction: the CALLER's
    /// slice cannot be zeroized from here — the caller owns that
    /// discipline).
    ///
    /// # Errors
    /// [`CacheError::Init`] when the key length is wrong or the
    /// directory cannot be created.
    pub fn with_key_bytes(dir: &Path, key: &[u8]) -> Result<Self, CacheError> {
        let key = Zeroizing::new(key.to_vec());
        if key.len() != KEY_LEN {
            return Err(CacheError::Init(format!(
                "the master key must be {KEY_LEN} bytes (got {})",
                key.len()
            )));
        }
        fs::create_dir_all(dir).map_err(|error| CacheError::Init(error.to_string()))?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|error| CacheError::Init(error.to_string()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            cipher,
        })
    }

    /// The file path for one cache key.
    fn file_for(&self, key: CacheKey) -> PathBuf {
        let name = match key {
            CacheKey::Certificate => "certificate",
            CacheKey::PrivateKey => "private-key",
            CacheKey::ApiSession => "api-session",
        };
        self.dir.join(format!("{name}.bin"))
    }

    /// Reads and decrypts one entry. The SIZE CAP applies to reads
    /// too (the gate review's P1): a foreign/corrupted file of any
    /// size is absence — never an unbounded allocation on the
    /// connection thread. The FILE NAME rides the AEAD as AAD (the
    /// gate review's P2): a swapped ciphertext between cache files
    /// fails the tag — reads as absence, never as the wrong value.
    fn read_entry(&self, key: CacheKey) -> Option<Vec<u8>> {
        let path = self.file_for(key);
        // Open ONCE, read through a BOUND (the bot's TOCTOU P2): the
        // pre-check + separate read could allocate for a file that
        // grew or was replaced between the two calls. The descriptor
        // + take() bound makes the allocation cap hold against
        // concurrent growth no matter what the path resolves to
        // afterwards. O_NONBLOCK (the bot round-10 P2): this read
        // runs on the STARTUP preload path, and a FIFO planted at an
        // entry path would BLOCK the plain open until a writer
        // appears — a nonblocking open returns the descriptor at
        // once, the bounded read sees EOF, and the entry reads as
        // absent (the corrupt-value arm) instead of hanging the
        // daemon. O_NONBLOCK is a no-op on regular files.
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&path)
                .ok()?
        };
        #[cfg(not(unix))]
        let file = fs::File::open(&path).ok()?;
        let mut bytes = Vec::new();
        std::io::Read::take(&mut &file, MAX_FILE_LEN + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > MAX_FILE_LEN {
            return None;
        }
        let (nonce, ciphertext) = split_entry(&bytes)?;
        let aad = path.file_name()?.to_string_lossy().into_owned();
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .ok()
    }

    /// Encrypts and writes one entry (0600, atomic-replace). The
    /// plaintext is ZEROIZED after the write (the gate review's P2:
    /// the WG private key leaves no heap residue — the same class
    /// as the at-rest discipline). The file NAME binds as AAD. The
    /// size cap is checked BEFORE encryption (the bot round-2 P2:
    /// an oversized value never allocates the ciphertext + file
    /// buffers — the refusal is typed and cheap).
    fn write_entry(&self, key: CacheKey, plaintext: Zeroizing<Vec<u8>>) -> Result<(), CacheError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(CacheError::Io(format!(
                "cache entry {} bytes exceeds the plaintext cap (the file cap \
                 {MAX_FILE_LEN} minus the 48-byte serialization overhead)",
                plaintext.len()
            )));
        }
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|error| CacheError::Io(format!("OS randomness: {error}")))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let path = self.file_for(key);
        let aad = path
            .file_name()
            .ok_or_else(|| CacheError::Io("no file name".to_owned()))?
            .to_string_lossy()
            .into_owned();
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| CacheError::Crypto("encryption failed".to_owned()))?;
        let mut file = MAGIC.to_vec();
        file.push(VERSION);
        file.extend_from_slice(&nonce_bytes);
        file.extend_from_slice(&ciphertext);
        write_private(&path, &file, &nonce_bytes)
    }

    /// The FALLIBLE write path (the bot round-2 P1): returns the
    /// error instead of warning-and-discarding, so the facade's
    /// worker can record it into the health surface. The plaintext
    /// zeroizes on every path.
    pub(crate) fn try_put(&self, key: CacheKey, bytes: Vec<u8>) -> Result<(), CacheError> {
        self.write_entry(key, Zeroizing::new(bytes))
    }

    /// The FALLIBLE removal path (the bot round-4 P1): a removal
    /// the filesystem rejects (read-only, full) returns the error —
    /// the worker records it; a NotFound is SUCCESS (the desired
    /// state already holds — but the DIRECTORY still syncs: a retry
    /// after remove-succeeded-but-sync-failed takes this arm and
    /// must not report durability the crash can contradict, the bot
    /// round-6 P2).
    pub(crate) fn try_remove(&self, key: CacheKey) -> Result<(), CacheError> {
        let path = self.file_for(key);
        match fs::remove_file(&path) {
            Ok(()) => sync_parent_dir(&path).map_err(CacheError::Io),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                sync_parent_dir(&path).map_err(CacheError::Io)
            }
            Err(error) => Err(CacheError::Io(error.to_string())),
        }
    }

    /// The FALLIBLE clear path (round 4): EVERY removal is
    /// attempted (the bot round-6 P1 — the `?` stopped at the
    /// first failure, leaving the later credentials on disk while
    /// the facade's memory view was already empty); the first
    /// failure is returned AFTER the sweep.
    ///
    /// Caller-less in the FACADE since the round-10 per-key
    /// expansion (the whole-bucket path is exactly what that fix
    /// removed) — the method stays: its sweep pin owns this
    /// cache-layer invariant directly.
    #[allow(dead_code)]
    pub(crate) fn try_clear_all(&self) -> Result<(), CacheError> {
        let mut first_failure = None;
        for key in [
            CacheKey::Certificate,
            CacheKey::PrivateKey,
            CacheKey::ApiSession,
        ] {
            if let Err(error) = self.try_remove(key)
                && first_failure.is_none()
            {
                first_failure = Some(error);
            }
        }
        first_failure.map_or(Ok(()), Err)
    }
}

/// Syncs a path's parent directory, PROPAGATING the failure (the
/// bot round-4 P2s: a discarded sync publishes a durability the
/// crash can contradict).
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        // A RELATIVE path with no directory component yields an EMPTY
        // parent (the bot round-13 P2): File::open("") would ENOENT
        // and fail the resync after a successful publish. The empty
        /// parent IS the current directory.
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let dir = fs::File::open(parent).map_err(|error| error.to_string())?;
        dir.sync_all().map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<(), String> {
    Ok(())
}

impl PersistentCache for EncryptedCache {
    fn put(&self, key: CacheKey, bytes: Vec<u8>) {
        // The connection thread must not die on a cache write: the
        // error is WARNED (the cache is an optimization, not a
        // commitment — ProTUN regenerates missing values) and the
        // plaintext zeroizes on drop.
        let name = format!("{key:?}");
        if let Err(error) = self.write_entry(key, Zeroizing::new(bytes)) {
            tracing::warn!(key = %name, %error, "persistent-cache write failed");
        }
    }

    fn get(&self, key: CacheKey) -> Option<Vec<u8>> {
        self.read_entry(key)
    }

    fn remove(&self, key: CacheKey) {
        let name = format!("{key:?}");
        if let Err(error) = self.try_remove(key) {
            tracing::warn!(key = %name, %error, "persistent-cache remove failed");
        }
    }

    fn clear_all(&self) {
        for key in [
            CacheKey::Certificate,
            CacheKey::PrivateKey,
            CacheKey::ApiSession,
        ] {
            self.remove(key);
        }
    }
}

/// Splits a cache file into (nonce, ciphertext), validating magic,
/// version, and length.
fn split_entry(bytes: &[u8]) -> Option<(&XNonce, &[u8])> {
    if bytes.len() < MAGIC.len() + 1 + NONCE_LEN {
        return None;
    }
    if &bytes[..MAGIC.len()] != MAGIC || bytes[MAGIC.len()] != VERSION {
        return None;
    }
    let nonce_start = MAGIC.len() + 1;
    let nonce = XNonce::from_slice(&bytes[nonce_start..nonce_start + NONCE_LEN]);
    Some((nonce, &bytes[nonce_start + NONCE_LEN..]))
}

/// Writes `bytes` to `path` as a NEW private (0600) file, with the
/// write-then-rename discipline (no partial reads by concurrent
/// getters). The gate review's P1 remediation: the temp file is
/// created 0600 FROM THE FIRST BYTE (`create_new` + `mode(0o600)`
/// — never a world-readable window, never following a pre-planted
/// symlink), carries a UNIQUE suffix (concurrent writers never
/// interleave on one inode), and is REMOVED on every failure path
/// (no keyfile residue at rest).
fn write_private(path: &Path, bytes: &[u8], nonce: &[u8; NONCE_LEN]) -> Result<(), CacheError> {
    if bytes.len() as u64 > MAX_FILE_LEN {
        return Err(CacheError::Io(format!(
            "cache entry {} bytes exceeds the {MAX_FILE_LEN} cap",
            bytes.len()
        )));
    }
    // The unique suffix: the FULL nonce, hex (the bot round-6 P2 —
    // 16 bits collided at 1/65,536 and the loser's cleanup removed
    // the WINNER's temp; 192 bits makes that unreachable and the
    // cleanup only ever unlinks this invocation's name).
    let temp = path.with_extension(format!("tmp{}", hex_slice(nonce)));
    let write = || -> Result<(), CacheError> {
        let mut file = open_new_private(&temp)?;
        // sync_all, not flush (the bot round-2 P2): the ciphertext is
        // DURABLE before the rename publishes it — a power loss
        // never publishes a name over unflushed bytes; the
        // parent-dir sync below completes the directory-entry side.
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| CacheError::Io(error.to_string()))?;
        Ok(())
    };
    if let Err(error) = write() {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(CacheError::Io(error.to_string()));
    }
    // The parent-directory sync, PROPAGATED (the bot round-4 P2): a
    // discarded failure would report durability a crash can
    // contradict.
    sync_parent_dir(path).map_err(CacheError::Io)?;
    Ok(())
}

/// A byte slice as hex (the temp suffix — the full nonce's 192
/// bits; no formatting machinery on the connection-thread path).
fn hex_slice(bytes: &[u8]) -> String {
    const HEX: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize]);
        out.push(HEX[(byte & 0xf) as usize]);
    }
    out
}

#[cfg(unix)]
fn open_new_private(path: &Path) -> Result<std::fs::File, CacheError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| CacheError::Io(error.to_string()))
}

#[cfg(not(unix))]
fn open_new_private(path: &Path) -> Result<std::fs::File, CacheError> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| CacheError::Io(error.to_string()))
}

/// Reads the keyfile WITH the no-follow + regular-file + mode +
/// owner validation (the bot round-1's P2 hardening of the reuse
/// path): the leaf is opened WITHOUT following symlinks; a symlink
/// keyfile, a non-regular file, or a wider-than-0600 mode refuses
/// typed. `Ok(None)` = absent (the first-use arm). The open is
/// NONBLOCKING (the bot round-10 P2): a FIFO at the keyfile path
/// would otherwise block this read-only open before the
/// regular-file check below can reject it — `EncryptedCache::open`
/// would hang initialization instead of refusing.
fn read_keyfile(key_path: &Path) -> Result<Option<Vec<u8>>, CacheError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(key_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(CacheError::KeyFile(
                    "the keyfile is a SYMLINK — refusing (a symlinked keyfile never rides)"
                        .to_owned(),
                ));
            }
            Err(error) => return Err(CacheError::KeyFile(error.to_string())),
        };
        let metadata = file
            .metadata()
            .map_err(|error| CacheError::KeyFile(error.to_string()))?;
        use std::os::unix::fs::PermissionsExt;
        if !metadata.is_file() {
            return Err(CacheError::KeyFile(
                "the keyfile is not a regular file — refusing".to_owned(),
            ));
        }
        let mode = metadata.permissions().mode();
        if mode & 0o777 != 0o600 {
            return Err(CacheError::KeyFile(format!(
                "the keyfile mode is {mode:o}, expected 0600 — refusing (a wider keyfile \
                 never rides silently; tighten it and retry)"
            )));
        }
        // The OWNER check (the bot round-2 P2): the keyfile must
        // belong to the READING user — a foreign-owned keyfile
        // (even mode-0600) never rides.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let expected = nix_uid();
            if metadata.uid() != expected {
                return Err(CacheError::KeyFile(format!(
                    "the keyfile owner is uid {}, expected {expected} (the reading user) — \
                     refusing",
                    metadata.uid()
                )));
            }
        }
        // Zeroizing FROM THE READ (the bot round-2 P2): the plain
        // Vec is wrapped before ANY fallible check — a wrong-length
        // or otherwise-refusing path frees key material zeroized.
        // The BOUNDED read (the bot round-3 P2): at most KEY_LEN + 1
        // bytes — a malformed huge keyfile cannot grow the buffer
        // before the length check refuses it.
        let mut bytes = Zeroizing::new(Vec::with_capacity(KEY_LEN));
        let mut file = file;
        std::io::Read::take(&mut file, KEY_LEN as u64 + 1)
            .read_to_end(bytes.as_mut())
            .map_err(|error| CacheError::KeyFile(error.to_string()))?;
        if bytes.len() != KEY_LEN {
            return Err(CacheError::KeyFile(format!(
                "the keyfile is {} bytes, expected {KEY_LEN} — refusing to re-key \
                 (existing cache files would be orphaned)",
                bytes.len()
            )));
        }
        // The RESYNC (the bot round-6 P2): a prior publish's
        // parent-dir sync may have FAILED after the hard_link —
        // this open re-establishes the keyfile's directory
        // durability before accepting it (ciphertext can otherwise
        // become durable while the key's directory entry stays
        // crash-volatile).
        sync_parent_dir(key_path).map_err(CacheError::KeyFile)?;
        Ok(Some(bytes.to_vec()))
    }
    #[cfg(not(unix))]
    {
        match fs::read(key_path) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                if bytes.len() != KEY_LEN {
                    return Err(CacheError::KeyFile(format!(
                        "the keyfile is {} bytes, expected {KEY_LEN} — refusing to re-key \
                         (existing cache files would be orphaned)",
                        bytes.len()
                    )));
                }
                Ok(Some(bytes.to_vec()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(CacheError::KeyFile(error.to_string())),
        }
    }
}

/// The reading user's uid (the keyfile owner check) — nix's safe
/// wrapper (no unsafe block in this crate).
#[cfg(unix)]
fn nix_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

/// The no-replace keyfile creation (the race P2's fix): the FINAL
/// path is created with create_new — a racing loser gets EEXIST and
/// reloads the winner's key.
enum CreateKeyfileError {
    /// Another initializer won the race.
    LostRace,
    /// An I/O failure (mapped).
    Io(CacheError),
}

fn create_keyfile_no_replace(
    key_path: &Path,
    key_bytes: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<(), CreateKeyfileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The ATOMIC PUBLISH (the bot round-3 P2): create_new made
        // the final pathname visible BEFORE the key bytes were
        // written — a racing loser could reload a still-empty file.
        // The fix: write a UNIQUE TEMP (create_new + 0600 + sync),
        // then publish with link() — an atomic no-replace rename; a
        // loser's link fails EEXIST against the winner's COMPLETE
        // file. The keyfile is the RAW 32 key bytes under 0600 (the
        // decision-(a) record).
        let temp = key_path.with_extension(format!("tmp{}", hex_slice(nonce)));
        let write = || -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(key_bytes)?;
            file.sync_all()?;
            Ok(())
        };
        if let Err(error) = write() {
            let _ = fs::remove_file(&temp);
            return Err(CreateKeyfileError::Io(CacheError::KeyFile(
                error.to_string(),
            )));
        }
        // link(): no-replace publish (EEXIST = lost the race), the
        // std-safe wrapper for a two-pathname syscall.
        if let Err(error) = fs::hard_link(&temp, key_path) {
            let _ = fs::remove_file(&temp);
            return if error.kind() == std::io::ErrorKind::AlreadyExists {
                Err(CreateKeyfileError::LostRace)
            } else {
                Err(CreateKeyfileError::Io(CacheError::KeyFile(
                    error.to_string(),
                )))
            };
        }
        let _ = fs::remove_file(&temp);
        // The dir sync PROPAGATED (the bot round-4 P2): a failed
        // sync after the hard_link means the key can vanish on
        // crash while ciphertext survives — the next startup
        // re-keys and orphans every entry. Reported, never assumed.
        sync_parent_dir(key_path)
            .map_err(CacheError::KeyFile)
            .map_err(CreateKeyfileError::Io)
    }
    #[cfg(not(unix))]
    {
        let _ = (key_path, key_bytes, nonce);
        Ok(())
    }
}

/// Cache failures. All variants carry NO key material (I/O paths
/// and sizes only).
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// The master keyfile could not be read, created, or is the
    /// wrong size.
    #[error("keyfile: {0}")]
    KeyFile(String),
    /// The cache could not be initialized.
    #[error("init: {0}")]
    Init(String),
    /// An I/O failure.
    #[error("io: {0}")]
    Io(String),
    /// An AEAD failure (tampering presents as this on read).
    #[error("crypto: {0}")]
    Crypto(String),
}

/// The test/placeholder cache: in-memory, no persistence, no crypto.
/// ProTUN generates and re-generates values through it without any
/// at-rest state (the PR-3/PR-4 hermetic lanes).
#[derive(Default)]
pub struct NullCache {
    inner: std::sync::Mutex<std::collections::HashMap<CacheKey, Vec<u8>>>,
}

impl PersistentCache for NullCache {
    fn put(&self, key: CacheKey, bytes: Vec<u8>) {
        self.inner
            .lock()
            .expect("null cache lock")
            .insert(key, bytes);
    }

    fn get(&self, key: CacheKey) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .expect("null cache lock")
            .get(&key)
            .cloned()
    }

    fn remove(&self, key: CacheKey) {
        self.inner.lock().expect("null cache lock").remove(&key);
    }

    fn clear_all(&self) {
        self.inner.lock().expect("null cache lock").clear();
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "protonwire-cache-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn key_bytes(seed: u8) -> Vec<u8> {
        vec![seed; KEY_LEN]
    }

    #[test]
    fn put_get_round_trips_through_disk() {
        let dir = temp_dir("roundtrip");
        let cache = EncryptedCache::with_key_bytes(&dir, &key_bytes(1)).unwrap();
        cache.put(CacheKey::PrivateKey, b"the-wg-key".to_vec());
        cache.put(CacheKey::Certificate, b"the-cert".to_vec());
        assert_eq!(
            cache.get(CacheKey::PrivateKey),
            Some(b"the-wg-key".to_vec())
        );
        assert_eq!(cache.get(CacheKey::Certificate), Some(b"the-cert".to_vec()));
        assert_eq!(cache.get(CacheKey::ApiSession), None);
    }

    /// The disk-scan canary (T-32's discipline): the on-disk bytes
    /// of every cache file contain NO plaintext — nor the master
    /// key, nor the raw nonce-only shape.
    #[test]
    fn the_disk_scan_canary_finds_no_plaintext() {
        let dir = temp_dir("canary");
        let master = key_bytes(7);
        let cache = EncryptedCache::with_key_bytes(&dir, &master).unwrap();
        let secret = b"SECRET-CERTIFICATE-BYTES-0123456789";
        cache.put(CacheKey::Certificate, secret.to_vec());
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "tmp") {
                panic!("a temp file survived the write: {path:?}");
            }
            let bytes = fs::read(&path).unwrap();
            let haystack = String::from_utf8_lossy(&bytes);
            assert!(
                !haystack.contains("SECRET-CERTIFICATE"),
                "PLAINTEXT AT REST in {path:?}"
            );
            assert!(
                !bytes.windows(KEY_LEN).any(|w| w == master.as_slice()),
                "THE MASTER KEY AT REST in {path:?}"
            );
        }
    }

    #[test]
    fn remove_and_clear_all_drop_the_entries() {
        let dir = temp_dir("remove");
        let cache = EncryptedCache::with_key_bytes(&dir, &key_bytes(2)).unwrap();
        cache.put(CacheKey::PrivateKey, b"k".to_vec());
        cache.remove(CacheKey::PrivateKey);
        assert_eq!(cache.get(CacheKey::PrivateKey), None);
        cache.put(CacheKey::ApiSession, b"s".to_vec());
        cache.clear_all();
        assert_eq!(cache.get(CacheKey::ApiSession), None);
        // clear_all on an empty cache is a no-op, not an error.
        cache.clear_all();
    }

    #[test]
    fn a_tampered_ciphertext_reads_as_absent() {
        let dir = temp_dir("tamper");
        let cache = EncryptedCache::with_key_bytes(&dir, &key_bytes(3)).unwrap();
        cache.put(CacheKey::Certificate, b"legit".to_vec());
        let path = cache.file_for(CacheKey::Certificate);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            cache.get(CacheKey::Certificate),
            None,
            "AEAD tampering presents as absence — never as corrupted plaintext"
        );
    }

    #[test]
    fn a_wrong_master_key_reads_as_absent() {
        let dir = temp_dir("wrongkey");
        let cache = EncryptedCache::with_key_bytes(&dir, &key_bytes(4)).unwrap();
        cache.put(CacheKey::Certificate, b"legit".to_vec());
        let other = EncryptedCache::with_key_bytes(&dir, &key_bytes(5)).unwrap();
        assert_eq!(other.get(CacheKey::Certificate), None);
    }

    #[test]
    fn open_creates_the_keyfile_private_and_reuses_it() {
        let dir = temp_dir("keyfile");
        let key_path = dir.join("cache.key");
        let cache = EncryptedCache::open(&dir.join("cache"), &key_path).unwrap();
        cache.put(CacheKey::PrivateKey, b"v".to_vec());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the keyfile is 0600 (decision (a))");
        }
        // Re-open: the SAME keyfile decrypts the entry.
        let reopened = EncryptedCache::open(&dir.join("cache"), &key_path).unwrap();
        assert_eq!(reopened.get(CacheKey::PrivateKey), Some(b"v".to_vec()));
    }

    #[test]
    fn a_truncated_keyfile_refuses_rather_than_rekeying() {
        let dir = temp_dir("truncated");
        let key_path = dir.join("cache.key");
        fs::write(&key_path, b"short").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let error = EncryptedCache::open(&dir.join("cache"), &key_path).unwrap_err();
        assert!(
            error.to_string().contains("refusing to re-key"),
            "orphaning the existing cache silently: {error}"
        );
    }

    #[test]
    fn the_wrong_key_length_refuses_typed() {
        let dir = temp_dir("keylen");
        assert!(matches!(
            EncryptedCache::with_key_bytes(&dir, b"short"),
            Err(CacheError::Init(_))
        ));
    }

    #[test]
    fn a_foreign_file_is_absent_never_a_panic() {
        let dir = temp_dir("foreign");
        let cache = EncryptedCache::with_key_bytes(&dir, &key_bytes(6)).unwrap();
        fs::write(cache.file_for(CacheKey::Certificate), b"junk").unwrap();
        assert_eq!(cache.get(CacheKey::Certificate), None);
    }

    #[test]
    fn the_oversized_entry_refuses() {
        let dir = temp_dir("oversize");
        let cache = EncryptedCache::with_key_bytes(&dir, &key_bytes(8)).unwrap();
        let error = cache
            .write_entry(CacheKey::Certificate, Zeroizing::new(vec![0u8; 100 * 1024]))
            .unwrap_err();
        assert!(error.to_string().contains("cap"), "{error}");
        // Through the trait: warned, not fatal.
        cache.put(CacheKey::Certificate, vec![0u8; 100 * 1024]);
    }

    #[test]
    fn the_null_cache_round_trips_in_memory() {
        let cache = NullCache::default();
        cache.put(CacheKey::ApiSession, b"s".to_vec());
        assert_eq!(cache.get(CacheKey::ApiSession), Some(b"s".to_vec()));
        cache.clear_all();
        assert_eq!(cache.get(CacheKey::ApiSession), None);
    }

    #[test]
    fn debug_never_renders_key_material() {
        let dir = temp_dir("debug");
        let cache = EncryptedCache::with_key_bytes(&dir, &key_bytes(9)).unwrap();
        let rendered = format!("{cache:?}");
        assert!(rendered.contains("XChaCha20-Poly1305"));
        assert!(
            !rendered.contains("AAAAAAAA"),
            "no key-derived bytes in Debug: {rendered}"
        );
    }

    /// The gate review's read-cap P1: a foreign file beyond the cap
    /// is ABSENCE — never an unbounded allocation on the connection
    /// thread.
    #[test]
    fn a_foreign_oversize_file_reads_as_absent() {
        let dir = temp_dir("oversizeread");
        let cache = EncryptedCache::with_key_bytes(&dir, &key_bytes(10)).unwrap();
        let path = cache.file_for(CacheKey::Certificate);
        fs::write(&path, vec![0u8; 100 * 1024]).unwrap();
        assert_eq!(
            cache.get(CacheKey::Certificate),
            None,
            "the cap refuses before the read allocates"
        );
    }

    /// The gate review's reuse-path mode P1: a PRE-EXISTING keyfile
    /// wider than 0600 refuses — a planted/restore-mangled keyfile
    /// never rides silently (pre-fix: the mode was never checked).
    #[test]
    fn a_too_wide_preexisting_keyfile_refuses() {
        let dir = temp_dir("widemode");
        let key_path = dir.join("cache.key");
        fs::write(&key_path, key_bytes(14)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
            let error = EncryptedCache::open(&dir.join("cache"), &key_path).unwrap_err();
            assert!(
                error.to_string().contains("0600"),
                "the refusal names the expected mode: {error}"
            );
            assert!(
                error.to_string().contains("644"),
                "the refusal names the observed mode: {error}"
            );
        }
    }

    /// The bot round-1's symlink P2: a SYMLINKED keyfile refuses
    /// (O_NOFOLLOW — a pre-provisioned pointer never rides).
    #[test]
    #[cfg(unix)]
    fn a_symlinked_keyfile_refuses() {
        let dir = temp_dir("symlink");
        let real = dir.join("real.key");
        fs::write(&real, key_bytes(16)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let link = dir.join("cache.key");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let error = EncryptedCache::open(&dir.join("cache"), &link).unwrap_err();
        assert!(
            error.to_string().contains("SYMLINK"),
            "the refusal names the symlink: {error}"
        );
    }

    /// The bot round-1's creation-race P2: when the final keyfile
    /// already exists at creation time, the loser RELOADS the
    /// winner's key (no-replace semantics — both instances converge
    /// on one key; entries never orphan).
    #[test]
    fn a_creation_race_converges_on_the_winners_key() {
        let dir = temp_dir("race");
        let key_path = dir.join("cache.key");
        let shared = dir.join("cache");
        // The "winner" creates first.
        let winner = EncryptedCache::open(&shared, &key_path).expect("the winner creates");
        drop(winner);
        // The "loser" would have observed NotFound — but by the time
        // it creates, the file exists: it reloads the winner's key.
        let loser = EncryptedCache::open(&shared, &key_path).expect("the loser loads");
        // The convergence proof: the loser's key decrypts the
        // winner's entry (one keyfile, one key).
        loser.put(CacheKey::Certificate, b"loser-writes".to_vec());
        let reader = EncryptedCache::open(&shared, &key_path).expect("a third reader");
        assert_eq!(
            reader.get(CacheKey::Certificate),
            Some(b"loser-writes".to_vec()),
            "one keyfile — one key — every instance reads the entries"
        );
    }

    /// The gate review's AAD P2: swapping two cache files' contents
    /// fails both tags — each reads as ABSENCE, never as the wrong
    /// value (pre-fix: the shared master key decrypted both fine).
    #[test]
    fn swapped_cache_files_read_as_absent() {
        let dir = temp_dir("swap");
        let cache = EncryptedCache::with_key_bytes(&dir, &key_bytes(15)).unwrap();
        cache.put(CacheKey::Certificate, b"cert-material".to_vec());
        cache.put(CacheKey::PrivateKey, b"key-material".to_vec());
        let cert_path = cache.file_for(CacheKey::Certificate);
        let key_path = cache.file_for(CacheKey::PrivateKey);
        let cert_bytes = fs::read(&cert_path).unwrap();
        let key_bytes_on_disk = fs::read(&key_path).unwrap();
        fs::write(&cert_path, key_bytes_on_disk).unwrap();
        fs::write(&key_path, cert_bytes).unwrap();
        assert_eq!(cache.get(CacheKey::Certificate), None, "the tag fails");
        assert_eq!(cache.get(CacheKey::PrivateKey), None, "both tags fail");
    }

    /// The gate review's temp-residue P1: a FAILED write leaves no
    /// .tmp behind (the pre-fix failure path leaked the temp — for
    /// the keyfile, the raw master key at rest).
    #[test]
    fn a_failed_write_leaves_no_temp_residue() {
        let dir = temp_dir("residue");
        let cache = EncryptedCache::with_key_bytes(&dir, &key_bytes(11)).unwrap();
        // A DIRECTORY at the final path makes the rename fail.
        let final_path = cache.file_for(CacheKey::PrivateKey);
        fs::create_dir_all(&final_path).unwrap();
        cache.put(CacheKey::PrivateKey, b"material".to_vec());
        let residue: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                path.extension()
                    .is_some_and(|ext| ext.to_string_lossy().starts_with("tmp"))
                    .then_some(path)
            })
            .collect();
        assert!(
            residue.is_empty(),
            "failure-path temp residue (the keyfile leak shape): {residue:?}"
        );
    }

    /// The gate review's nonce-freshness pin: two writes of the same
    /// key carry DIFFERENT nonces (file offset 8..32) — the no-reuse
    /// property under random nonces.
    #[test]
    fn two_writes_of_one_key_carry_different_nonces() {
        let dir = temp_dir("nonce");
        let cache = EncryptedCache::with_key_bytes(&dir, &key_bytes(12)).unwrap();
        cache.put(CacheKey::Certificate, b"same-plaintext".to_vec());
        let first = fs::read(cache.file_for(CacheKey::Certificate)).unwrap();
        cache.put(CacheKey::Certificate, b"same-plaintext".to_vec());
        let second = fs::read(cache.file_for(CacheKey::Certificate)).unwrap();
        fn nonce_of(bytes: &[u8]) -> &[u8] {
            &bytes[MAGIC.len() + 1..MAGIC.len() + 1 + NONCE_LEN]
        }
        assert_ne!(
            nonce_of(&first),
            nonce_of(&second),
            "every put draws a fresh nonce"
        );
    }

    /// The gate review's concurrency pin: concurrent put/get across
    /// threads — the unique temp suffix means no interleaved writes;
    /// a torn read presents as absence via the AEAD.
    #[test]
    fn concurrent_puts_and_gets_stay_coherent() {
        let dir = temp_dir("concurrent");
        let cache =
            std::sync::Arc::new(EncryptedCache::with_key_bytes(&dir, &key_bytes(13)).unwrap());
        let writers: Vec<_> = (0..4)
            .map(|worker| {
                let cache = std::sync::Arc::clone(&cache);
                std::thread::spawn(move || {
                    for round in 0..50 {
                        cache.put(
                            CacheKey::Certificate,
                            format!("w{worker}-r{round}").into_bytes(),
                        );
                        // A concurrent read: the value is the LAST
                        // completed rename or absence — never torn
                        // plaintext.
                        if let Some(value) = cache.get(CacheKey::Certificate) {
                            let text = String::from_utf8(value).unwrap();
                            assert!(text.starts_with('w'), "a torn read surfaced: {text:?}");
                        }
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().expect("no writer panics");
        }
        // The final state decrypts (the winner is one whole write).
        let final_value = cache.get(CacheKey::Certificate).expect("a final value");
        assert!(String::from_utf8(final_value).unwrap().starts_with('w'));
        // And no temp residue survived the concurrent window.
        let residue = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                path.extension()
                    .is_some_and(|ext| ext.to_string_lossy().starts_with("tmp"))
                    .then_some(path)
            })
            .count();
        assert_eq!(residue, 0, "concurrent-writer temp residue");
    }
}
#[cfg(test)]
mod round5_tests {
    use super::*;
    use protun::api::connection::{CacheKey, PersistentCache};

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "protonwire-r5-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The bot round-5 P2: the plaintext cap accounts for the FULL
    /// serialization overhead — a plaintext at exactly the bound
    /// round-trips (pre-fix: the +48 file bytes crossed the file
    /// cap and the value vanished after restart).
    #[test]
    fn a_plaintext_at_the_bound_round_trips() {
        let dir = temp_dir("bound");
        let cache = EncryptedCache::with_key_bytes(&dir, &[12u8; 32]).unwrap();
        let at_bound = vec![0xa5u8; MAX_PLAINTEXT_LEN];
        cache.put(CacheKey::Certificate, at_bound.clone());
        assert_eq!(
            cache.get(CacheKey::Certificate),
            Some(at_bound),
            "at-the-bound plaintext persists (the overhead is accounted)"
        );
        // One byte past: the typed refusal at BOTH layers' line.
        let over = Zeroizing::new(vec![0xa5u8; MAX_PLAINTEXT_LEN + 1]);
        cache.put(CacheKey::PrivateKey, over.to_vec());
        assert_eq!(cache.get(CacheKey::PrivateKey), None);
    }

    /// The bot round-10 P2s: special files at the cache paths must
    /// fail fast, never block. A FIFO at an entry path or the
    /// keyfile path would hang the PLAIN read-only open until a
    /// writer appears — on the startup preload path that is a hung
    /// daemon. The nonblocking opens make both read as
    /// absent/refusal deterministically (mkfifo, then open with a
    /// generous-but-bounded join: the pre-fix shape would exceed it).
    #[test]
    #[cfg(unix)]
    fn special_files_fail_fast_instead_of_blocking() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::OpenOptionsExt;
        let dir = std::env::temp_dir().join(format!(
            "pw-fifo-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // A FIFO at the keyfile path: open must REFUSE (typed), not
        // block. Run it on a thread so a regression fails the
        // deadline instead of hanging the test runner.
        let key_fifo = dir.join("cache.key");
        let mk = || {
            #[allow(unsafe_code)] // workspace deny; mkfifo is a leaf syscall, no pointers
            unsafe {
                libc::mkfifo(key_fifo.as_os_str().as_bytes().as_ptr().cast(), 0o600)
            }
        };
        assert_eq!(mk(), 0, "mkfifo keyfile");
        let probe = std::thread::spawn({
            let path = key_fifo.clone();
            move || {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&path)
            }
        });
        let opened = probe
            .join()
            .expect("the probe thread must finish — the open is nonblocking");
        let metadata = opened
            .expect("a read-only O_NONBLOCK FIFO open succeeds at once")
            .metadata()
            .unwrap();
        assert!(
            !metadata.is_file(),
            "the regular-file check rejects the FIFO (the pre-fix shape blocked before reaching it)"
        );
        let _ = std::fs::remove_file(&key_fifo);

        // A FIFO at an ENTRY path: the preload read treats it as
        // absent (EOF under the bound) instead of blocking startup.
        let entry_fifo = dir.join("certificate.bin");
        #[allow(unsafe_code)] // workspace deny; mkfifo is a leaf syscall, no pointers
        unsafe {
            libc::mkfifo(entry_fifo.as_os_str().as_bytes().as_ptr().cast(), 0o600)
        };
        let cache = super::EncryptedCache::with_key_bytes(&dir, &[31u8; 32]).unwrap();
        let read = cache.get(protun::api::connection::CacheKey::Certificate);
        assert_eq!(read, None, "the FIFO entry reads as absent, promptly");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The bot round-13 P2: a RELATIVE key path with no directory
    /// component — `Path::new("cache.key")` — has an EMPTY parent,
    /// not None: the sync must treat that as the current directory
    /// (File::open("") would ENOENT and fail the resync after a
    /// successful publish).
    #[test]
    fn a_relative_key_path_syncs_the_current_directory() {
        let dir = std::env::temp_dir().join(format!(
            "pw-relkey-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Run from inside the temp dir: the key path is a BARE
        // filename (empty parent).
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let result = EncryptedCache::open(Path::new("."), Path::new("cache.key"));
        std::env::set_current_dir(previous).unwrap();
        let cache = result.expect("a bare-filename key path opens (the empty parent syncs as .)");
        cache
            .try_put(CacheKey::Certificate, b"cert".to_vec())
            .expect("the round-trip works");
        std::fs::remove_dir_all(&dir).ok();
    }
}
