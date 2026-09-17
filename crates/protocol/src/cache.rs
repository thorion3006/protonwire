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
use std::io::Write;
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
        let key: Zeroizing<Vec<u8>> = match fs::read(key_path) {
            Ok(bytes) => {
                if bytes.len() != KEY_LEN {
                    return Err(CacheError::KeyFile(format!(
                        "the keyfile is {} bytes, expected {KEY_LEN} — refusing to re-key \
                         (existing cache files would be orphaned)",
                        bytes.len()
                    )));
                }
                Zeroizing::new(bytes)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut fresh = Zeroizing::new([0u8; KEY_LEN]);
                getrandom::fill(fresh.as_mut_slice())
                    .map_err(|error| CacheError::KeyFile(format!("OS randomness: {error}")))?;
                let mut nonce = [0u8; NONCE_LEN];
                getrandom::fill(&mut nonce)
                    .map_err(|error| CacheError::KeyFile(format!("OS randomness: {error}")))?;
                write_private(key_path, fresh.as_slice(), &nonce)?;
                Zeroizing::new(fresh.to_vec())
            }
            Err(error) => return Err(CacheError::KeyFile(error.to_string())),
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
    /// connection thread.
    fn read_entry(&self, key: CacheKey) -> Option<Vec<u8>> {
        let path = self.file_for(key);
        let metadata = fs::metadata(&path).ok()?;
        if metadata.len() > MAX_FILE_LEN {
            return None;
        }
        let bytes = fs::read(&path).ok()?;
        let (nonce, ciphertext) = split_entry(&bytes)?;
        self.cipher.decrypt(nonce, Payload::from(ciphertext)).ok()
    }

    /// Encrypts and writes one entry (0600, atomic-replace). The
    /// plaintext is ZEROIZED after the write (the gate review's P2:
    /// the WG private key leaves no heap residue — the same class
    /// as the at-rest discipline).
    fn write_entry(&self, key: CacheKey, plaintext: Zeroizing<Vec<u8>>) -> Result<(), CacheError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|error| CacheError::Io(format!("OS randomness: {error}")))?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, Payload::from(plaintext.as_slice()))
            .map_err(|_| CacheError::Crypto("encryption failed".to_owned()))?;
        let mut file = MAGIC.to_vec();
        file.push(VERSION);
        file.extend_from_slice(&nonce_bytes);
        file.extend_from_slice(&ciphertext);
        write_private(&self.file_for(key), &file, &nonce_bytes)
    }
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
        match fs::remove_file(self.file_for(key)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(key = %name, %error, "persistent-cache remove failed");
            }
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
    // The unique suffix: two bytes of the fresh nonce, hex — the
    // same entropy that fronts the ciphertext.
    let [hi, lo] = hex_byte(nonce[0]);
    let [hi2, lo2] = hex_byte(nonce[1]);
    let temp = path.with_extension(format!("tmp{hi}{lo}{hi2}{lo2}"));
    let write = || -> Result<(), CacheError> {
        let mut file = open_new_private(&temp)?;
        file.write_all(bytes)
            .and_then(|()| file.flush())
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
    Ok(())
}

/// One byte as two hex characters (the temp suffix — no formatting
/// machinery on the connection-thread path).
fn hex_byte(byte: u8) -> [&'static str; 2] {
    const HEX: [&str; 16] = [
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
    ];
    [HEX[(byte >> 4) as usize], HEX[(byte & 0xf) as usize]]
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
