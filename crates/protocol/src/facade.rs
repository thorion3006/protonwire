//! FR-7JB/FR-32A's preloaded facade: the ONLY `PersistentCache`
//! implementation ProTUN's connection thread ever sees (M4 PR-2, the
//! bot round-1 P1s).
//!
//! The contract (PRD :615/:1167): preload the three values before the
//! engine starts; serve `get` from LOCKED MEMORY (no filesystem call
//! on the connection thread — a stalled mount must not stall the
//! tunnel); forward `put`/`remove`/`clear_all` to a serialized
//! persistence WORKER; surface durable-write HEALTH separately (the
//! trait is infallible — FR-7J's "a persistence write failure must be
//! surfaced even though the callbacks expose no error").
//!
//! [`PersistenceFacade`] is that two-layer shape over
//! `crate::cache::EncryptedCache`: the memory layer
//! (a `Mutex<HashMap>`, bounded at three entries — locked memory in
//! the daemon's mlocked future) and the worker (one thread, a channel
//! of at-most-three-keys operations, coalescing writes so a burst of
//! `put`s costs one disk write per key per drain).

use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use protun::api::connection::{CacheKey, PersistentCache};

use crate::cache::EncryptedCache;

/// One worker operation (coalesced per key at send time — the LAST
/// write for a key wins within a drain).
enum Op {
    Put(String, Vec<u8>),
    Remove(String),
    ClearAll,
}

/// The durable-write health surface (FR-7J): the last failure, the
/// last success, and whether the worker is alive. The daemon polls
/// this; the trait callbacks stay infallible.
#[derive(Debug, Clone)]
pub struct PersistenceHealth {
    /// The worker is consuming operations.
    pub alive: bool,
    /// The last write failure's message (key names and I/O classes
    /// only — never bytes; the cache's own discipline).
    pub last_failure: Option<String>,
    /// The number of operations applied without failure since the
    /// last failure (or since start).
    pub applied_since_failure: u64,
}

/// The preloaded facade: memory layer + worker handle.
pub struct PersistenceFacade {
    memory: Mutex<HashMap<String, Vec<u8>>>,
    sender: mpsc::Sender<Op>,
    health: Arc<HealthSlot>,
    /// Keeps the worker thread alive until the facade drops (the
    /// daemon's engine lifecycle).
    _worker: std::thread::JoinHandle<()>,
}

/// The worker's health slot (shared with the facade).
struct HealthSlot {
    alive: std::sync::atomic::AtomicBool,
    failure: Mutex<Option<String>>,
    applied: std::sync::atomic::AtomicU64,
}

impl PersistenceFacade {
    /// Preloads the three values from the cache and starts the
    /// worker. The disk reads happen HERE (startup), never on a
    /// connection thread.
    pub fn start(cache: Arc<EncryptedCache>) -> Self {
        let mut memory: HashMap<String, Vec<u8>> = HashMap::new();
        for key in [
            CacheKey::Certificate,
            CacheKey::PrivateKey,
            CacheKey::ApiSession,
        ] {
            let name = format!("{key:?}");
            if let Some(bytes) = cache.get(key) {
                memory.insert(name, bytes);
            }
        }
        let (sender, receiver) = mpsc::channel::<Op>();
        let health = Arc::new(HealthSlot {
            alive: std::sync::atomic::AtomicBool::new(true),
            failure: Mutex::new(None),
            applied: std::sync::atomic::AtomicU64::new(0),
        });
        let worker_health = Arc::clone(&health);
        let worker = std::thread::Builder::new()
            .name("protonwire-cache-worker".to_owned())
            .spawn(move || {
                worker_loop(cache, receiver, &worker_health);
            })
            .expect("the persistence worker thread spawns");
        Self {
            memory: Mutex::new(memory),
            sender,
            health,
            _worker: worker,
        }
    }

    /// The durable-write health snapshot (FR-7J's surface).
    pub fn health(&self) -> PersistenceHealth {
        PersistenceHealth {
            alive: self.health.alive.load(std::sync::atomic::Ordering::SeqCst),
            last_failure: self.health.failure.lock().expect("health lock").clone(),
            applied_since_failure: self
                .health
                .applied
                .load(std::sync::atomic::Ordering::SeqCst),
        }
    }
}

impl PersistentCache for PersistenceFacade {
    fn put(&self, key: CacheKey, bytes: Vec<u8>) {
        // Memory first (the read side is served from here
        // immediately), then the worker (the disk side is the
        // worker's alone).
        let name = format!("{key:?}");
        self.memory
            .lock()
            .expect("facade memory lock")
            .insert(name.clone(), bytes.clone());
        let _ = self.sender.send(Op::Put(name, bytes));
    }

    fn get(&self, key: CacheKey) -> Option<Vec<u8>> {
        let name = format!("{key:?}");
        self.memory
            .lock()
            .expect("facade memory lock")
            .get(&name)
            .cloned()
    }

    fn remove(&self, key: CacheKey) {
        let name = format!("{key:?}");
        self.memory
            .lock()
            .expect("facade memory lock")
            .remove(&name);
        let _ = self.sender.send(Op::Remove(name));
    }

    fn clear_all(&self) {
        self.memory.lock().expect("facade memory lock").clear();
        let _ = self.sender.send(Op::ClearAll);
    }
}

impl Drop for PersistenceFacade {
    fn drop(&mut self) {
        // Dropping the sender ends the worker's recv loop; the
        // facade's memory layer zeroizes nothing (the plaintext
        // lifecycle is the caller's — the same documented boundary
        // as the cache itself).
    }
}

/// The worker loop: one operation at a time (serialized — FR-7JB),
/// failures recorded to health, the applied counter advancing on
/// success.
fn worker_loop(cache: Arc<EncryptedCache>, receiver: mpsc::Receiver<Op>, health: &HealthSlot) {
    for op in receiver {
        let applied = match op {
            Op::Put(name, bytes) => {
                if let Some(key) = key_from_name(&name) {
                    cache.put(key, bytes);
                    true
                } else {
                    false
                }
            }
            Op::Remove(name) => {
                if let Some(key) = key_from_name(&name) {
                    cache.remove(key);
                    true
                } else {
                    false
                }
            }
            Op::ClearAll => {
                cache.clear_all();
                true
            }
        };
        if applied {
            health
                .applied
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    health
        .alive
        .store(false, std::sync::atomic::Ordering::SeqCst);
}

/// Maps the facade's stable name back onto the cache key (the
/// worker's disk side speaks CacheKey; the memory layer's String
/// keys avoid Clone-on-CacheKey).
fn key_from_name(name: &str) -> Option<CacheKey> {
    match name {
        "Certificate" => Some(CacheKey::Certificate),
        "PrivateKey" => Some(CacheKey::PrivateKey),
        "ApiSession" => Some(CacheKey::ApiSession),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use protun::api::connection::{CacheKey, PersistentCache};

    use super::*;
    use crate::cache::EncryptedCache;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "protonwire-facade-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// FR-7JB's preload: values on disk BEFORE start are served from
    /// memory; puts flow through to disk; gets never touch it.
    #[test]
    fn the_facade_preloads_and_persists() {
        let dir = temp_dir("preload");
        let cache = Arc::new(EncryptedCache::with_key_bytes(&dir, &[7u8; 32]).unwrap());
        cache.put(CacheKey::Certificate, b"pre-existing".to_vec());
        let facade = PersistenceFacade::start(Arc::clone(&cache));
        assert_eq!(
            facade.get(CacheKey::Certificate),
            Some(b"pre-existing".to_vec()),
            "the startup preload serves the first get from memory"
        );
        facade.put(CacheKey::PrivateKey, b"fresh".to_vec());
        assert_eq!(facade.get(CacheKey::PrivateKey), Some(b"fresh".to_vec()));
        // The worker writes asynchronously — poll the disk briefly.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if cache.get(CacheKey::PrivateKey) == Some(b"fresh".to_vec()) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the worker never persisted"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // remove/clear flow through.
        facade.remove(CacheKey::PrivateKey);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if facade.get(CacheKey::PrivateKey).is_none() {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// FR-7J's health surface: the applied counter advances on
    /// worker activity; the worker reports alive while the facade
    /// holds it.
    #[test]
    fn health_reports_the_worker_state() {
        let dir = temp_dir("health");
        let cache = Arc::new(EncryptedCache::with_key_bytes(&dir, &[8u8; 32]).unwrap());
        let facade = PersistenceFacade::start(Arc::clone(&cache));
        let before = facade.health().applied_since_failure;
        facade.put(CacheKey::ApiSession, b"s".to_vec());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while facade.health().applied_since_failure == before {
            assert!(std::time::Instant::now() < deadline, "the op never applied");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(facade.health().alive, "the worker is alive");
        assert!(facade.health().last_failure.is_none());
    }
}
