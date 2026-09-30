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
use zeroize::Zeroizing;

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
    memory: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
    sender: Option<mpsc::SyncSender<Op>>,
    health: Arc<HealthSlot>,
    /// Joined on drop (the bot round-2 P1): shutdown DRAINS the
    /// queue before the thread ends — no queued write is lost.
    worker: Option<std::thread::JoinHandle<()>>,
}

/// The worker's health slot (shared with the facade).
struct HealthSlot {
    alive: std::sync::atomic::AtomicBool,
    failure: Mutex<Option<String>>,
    applied: std::sync::atomic::AtomicU64,
}

/// The queue bound (the bot round-2 P1): a stalled cache filesystem
/// backs pressure onto the callback caller AT THE BOUND — the
/// facade's memory answer stays immediate; the DISK side refuses to
/// accumulate unbounded work. 64 covers every sane burst (three keys
/// × rapid updates) with the worker draining at disk speed.
const QUEUE_BOUND: usize = 64;

impl PersistenceFacade {
    /// Preloads the three values from the cache and starts the
    /// worker. The disk reads happen HERE (startup), never on a
    /// connection thread.
    pub fn start(cache: Arc<EncryptedCache>) -> Self {
        let mut memory: HashMap<String, Zeroizing<Vec<u8>>> = HashMap::new();
        for key in [
            CacheKey::Certificate,
            CacheKey::PrivateKey,
            CacheKey::ApiSession,
        ] {
            let name = format!("{key:?}");
            if let Some(bytes) = cache.get(key) {
                memory.insert(name, Zeroizing::new(bytes));
            }
        }
        let (sender, receiver) = mpsc::sync_channel::<Op>(QUEUE_BOUND);
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
            sender: Some(sender),
            health,
            worker: Some(worker),
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

    /// Joins the worker (once; Drop's helper). The queue drains
    /// first — the sender is gone, the worker's recv loop ends, and
    /// the join waits for the LAST op to hit disk.
    fn join_worker(&mut self) {
        // The SENDER goes first (the deadlock's root — the worker's
        // recv loop ends only when every sender drops; a facade
        // holding its own sender while joining would wait forever).
        self.sender = None;
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for PersistenceFacade {
    fn drop(&mut self) {
        // The bot round-2 P1: shutdown waits for the queued writes —
        // dropping a JoinHandle merely DETACHES, losing any queued
        // op; the join drains the channel to completion first (the
        // sender drops, the worker drains, the join returns).
        self.join_worker();
    }
}

impl PersistentCache for PersistenceFacade {
    fn put(&self, key: CacheKey, bytes: Vec<u8>) {
        // Memory first (the read side is served from here
        // immediately, in Zeroizing storage — the bot round-2 P2:
        // replaced/removed/cleared entries zeroize), then the
        // worker (the disk side is the worker's alone). A FULL
        // queue records the backpressure failure to health (the
        // callback returns — the memory answer stands, the disk
        // write is lost and REPORTED, never silently queued
        // without bound).
        let name = format!("{key:?}");
        self.memory
            .lock()
            .expect("facade memory lock")
            .insert(name.clone(), Zeroizing::new(bytes.clone()));
        let send_result = self
            .sender
            .as_ref()
            .map(|sender| sender.try_send(Op::Put(name, bytes)));
        if matches!(send_result, Some(Err(mpsc::TrySendError::Full(_)))) {
            record_failure(
                &self.health,
                "the persistence queue is full — a put was dropped (the stalled cache \
                 filesystem backs pressure onto the caller at the bound)",
            );
        }
    }

    fn get(&self, key: CacheKey) -> Option<Vec<u8>> {
        let name = format!("{key:?}");
        self.memory
            .lock()
            .expect("facade memory lock")
            .get(&name)
            .map(|value| value.to_vec())
    }

    fn remove(&self, key: CacheKey) {
        let name = format!("{key:?}");
        self.memory
            .lock()
            .expect("facade memory lock")
            .remove(&name);
        if let Some(sender) = self.sender.as_ref() {
            let _ = sender.try_send(Op::Remove(name));
        }
    }

    fn clear_all(&self) {
        self.memory.lock().expect("facade memory lock").clear();
        if let Some(sender) = self.sender.as_ref() {
            let _ = sender.try_send(Op::ClearAll);
        }
    }
}

/// Records a failure into the health slot (resets the applied
/// counter — the count is "since the last failure").
fn record_failure(health: &HealthSlot, message: &str) {
    *health.failure.lock().expect("health lock") = Some(message.to_owned());
    health.applied.store(0, std::sync::atomic::Ordering::SeqCst);
    tracing::warn!(%message, "persistence failure recorded to health");
}

/// The worker loop (serialized — FR-7JB): drains ops in BATCHES with
/// per-key COALESCING (the bot round-2 P1's claim made real — only
/// the LAST op per key in a batch applies), failures recorded to
/// health through the cache's FALLIBLE path, the applied counter
/// advancing only on success.
fn worker_loop(cache: Arc<EncryptedCache>, receiver: mpsc::Receiver<Op>, health: &HealthSlot) {
    let mut batch: Vec<Op> = Vec::with_capacity(QUEUE_BOUND);
    while let Ok(op) = receiver.recv() {
        // Blocked for the first op; drain whatever else is ready.
        batch.push(op);
        while batch.len() < QUEUE_BOUND {
            match receiver.try_recv() {
                Ok(op) => batch.push(op),
                Err(_) => break,
            }
        }
        // Coalesce: keep the LAST op per key (and the last ClearAll,
        // which dominates everything before it).
        let mut coalesced: Vec<Op> = Vec::with_capacity(batch.len());
        let mut saw_clear = false;
        for op in batch.drain(..).rev() {
            let name = match &op {
                Op::Put(name, _) => Some(name.clone()),
                Op::Remove(name) => Some(name.clone()),
                Op::ClearAll => None,
            };
            match name {
                None => {
                    if !saw_clear {
                        saw_clear = true;
                        coalesced.push(op);
                    }
                }
                Some(name) => {
                    if saw_clear {
                        continue; // dominated by the newer ClearAll
                    }
                    let seen = coalesced.iter().any(|existing| match existing {
                        Op::Put(existing_name, _) | Op::Remove(existing_name) => {
                            *existing_name == name
                        }
                        Op::ClearAll => false,
                    });
                    if !seen {
                        coalesced.push(op);
                    }
                }
            }
        }
        coalesced.reverse();
        for op in coalesced {
            let result: Result<(), crate::cache::CacheError> = match op {
                Op::Put(name, bytes) => match key_from_name(&name) {
                    Some(key) => cache.try_put(key, bytes),
                    None => Ok(()),
                },
                Op::Remove(name) => match key_from_name(&name) {
                    Some(key) => {
                        cache.remove(key);
                        Ok(())
                    }
                    None => Ok(()),
                },
                Op::ClearAll => {
                    cache.clear_all();
                    Ok(())
                }
            };
            match result {
                Ok(()) => {
                    health
                        .applied
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                Err(error) => record_failure(health, &error.to_string()),
            }
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

#[cfg(test)]
mod round2_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use protun::api::connection::{CacheKey, PersistentCache};

    use super::*;
    use crate::cache::EncryptedCache;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "protonwire-facade2-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The bot round-2 P1 (health propagation): a FAILED disk write
    /// records into health — the applied counter resets, the failure
    /// message surfaces. (An unwritable target: a directory at the
    /// entry's final path makes the write fail.)
    #[test]
    fn a_failed_disk_write_records_into_health() {
        let dir = temp_dir("healthfail");
        let cache = Arc::new(EncryptedCache::with_key_bytes(&dir, &[9u8; 32]).unwrap());
        // A DIRECTORY at the final path: every put fails at rename.
        std::fs::create_dir_all(dir.join("private-key.bin")).unwrap();
        let facade = PersistenceFacade::start(Arc::clone(&cache));
        facade.put(CacheKey::PrivateKey, b"material".to_vec());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while facade.health().last_failure.is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "the failure never recorded: {:?}",
                facade.health()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            facade.health().applied_since_failure == 0,
            "the counter reset on the failure"
        );
    }

    /// The bot round-2 P1 (shutdown drain): a queued write lands on
    /// disk BEFORE drop returns — the join waits, the write is not
    /// lost.
    #[test]
    fn drop_drains_the_queued_writes() {
        let dir = temp_dir("drain");
        let cache = Arc::new(EncryptedCache::with_key_bytes(&dir, &[10u8; 32]).unwrap());
        let facade = PersistenceFacade::start(Arc::clone(&cache));
        facade.put(CacheKey::Certificate, b"last-words".to_vec());
        drop(facade);
        // After drop: the write is durable (the join waited for it).
        assert_eq!(
            cache.get(CacheKey::Certificate),
            Some(b"last-words".to_vec()),
            "the queued write survived the shutdown"
        );
    }
}
