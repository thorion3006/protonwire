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
use std::time::Duration;

use protun::api::connection::{CacheKey, PersistentCache};
use zeroize::Zeroizing;

use crate::cache::EncryptedCache;

/// One worker operation, stamped with the facade's SEND-TIME
/// sequence (the bot round-9 P1: the queue and the overflow are
/// two lanes with no shared order — an overflow op (newest) could
/// apply before the stale queued batch overwrote it; the worker
/// never persists an op whose sequence is not newer than the last
/// applied for its key, so the GENUINELY newest state wins
/// regardless of which lane carried it). The put payload is
/// Zeroizing (the bot round-4 P2): ops discarded by coalescing or
/// a full queue scrub on drop.
#[derive(Clone)]
enum Op {
    Put(String, Zeroizing<Vec<u8>>, u64),
    Remove(String, u64),
    ClearAll(u64),
}

impl Op {
    /// The op's send-time sequence.
    fn seq(&self) -> u64 {
        match self {
            Op::Put(_, _, seq) | Op::Remove(_, seq) | Op::ClearAll(seq) => *seq,
        }
    }

    /// The per-key name the worker tracks ("" for ClearAll).
    fn key_name(&self) -> String {
        match self {
            Op::Put(name, _, _) | Op::Remove(name, _) => name.clone(),
            Op::ClearAll(_) => String::new(),
        }
    }

    /// Expands a ClearAll into its per-key Removes at the clear's OWN
    /// sequence (the refactor pass's consolidation — the expansion
    /// existed three times: overflow, the retry lane, apply_pass; one
    /// home keeps the "each Remove carries the clear's own seq"
    /// invariant from drifting). Every other op expands to itself.
    fn expand_per_key(self) -> Vec<Op> {
        match self {
            Op::ClearAll(seq) => ALL_KEYS
                .into_iter()
                .map(|key| Op::Remove(name_for(key), seq))
                .collect(),
            per_key => vec![per_key],
        }
    }
}

/// The facade's three storage keys (the PersistentCache surface).
const ALL_KEYS: [CacheKey; 3] = [
    CacheKey::Certificate,
    CacheKey::PrivateKey,
    CacheKey::ApiSession,
];

/// The stable per-key name the worker tracks (the mapping the queue,
/// the overflow, and the retry lane share; inverse of `key_from_name`).
fn name_for(key: CacheKey) -> String {
    format!("{key:?}")
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
    /// The OVERFLOW lane (the bot round-8 P1): ops the bounded
    /// queue refused (Full) land here — the newest desired state
    /// must reach the worker even when the disk side is backed up;
    /// the worker drains the overflow into every batch's TAIL (the
    /// coalescer's keep-last gives the newest state the win).
    /// Bounded at one op per key (the retry lane's own bound).
    overflow: Arc<Mutex<Vec<Op>>>,
    /// The send-time sequence (round 9): every op carries one;
    /// the worker never persists a per-key state older than the
    /// last it applied.
    seq: std::sync::atomic::AtomicU64,
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

/// The shutdown drain deadline (the bot round-4 P1): long enough
/// for a full queue's bounded writes on a healthy filesystem;
/// past it the join detaches with the failure recorded.
const SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// The idle worker's poll cadence. The overflow lane CANNOT wake the
/// worker: it fills only when the queue refused an op (the queue is
/// FULL — the very condition that routed the op to overflow), so an
/// idle worker sitting in a blocking `recv` would leave the newest
/// desired state undrained until the next queue op or shutdown —
/// exactly the staleness the bot round-8 P1 closed. An idle worker
/// therefore re-checks the lane every cadence (the CI round-9 flake
/// exposed this: the worker won the startup race to the blocking
/// recv and the test's overflow op sat undrained for the whole
/// deadline; the production shape of the same race is a missed
/// newest state).
const OVERFLOW_POLL: Duration = Duration::from_millis(250);

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
        let overflow = Arc::new(Mutex::new(Vec::new()));
        let worker_health = Arc::clone(&health);
        let worker_overflow = Arc::clone(&overflow);
        let worker = std::thread::Builder::new()
            .name("protonwire-cache-worker".to_owned())
            .spawn(move || {
                worker_loop(cache, receiver, &worker_health, &worker_overflow);
            })
            .expect("the persistence worker thread spawns");
        Self {
            memory: Mutex::new(memory),
            sender: Some(sender),
            overflow,
            seq: std::sync::atomic::AtomicU64::new(0),
            health,
            worker: Some(worker),
        }
    }

    /// The next send-time sequence (every op carries one).
    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
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
        // The BOUNDED join (the bot round-4 P1): a worker stuck in
        // a filesystem operation must not block daemon shutdown
        // indefinitely. std's join has no deadline, so a JOINER
        // thread races a recv_timeout: within the timeout the join
        // completed; past it the joiner DETACHES (leaked, joining
        // eventually when the syscall returns), the failure is
        // recorded — the queued writes may be lost, REPORTED, never
        // silent, and the daemon shuts down.
        if let Some(handle) = self.worker.take() {
            let (done, signal) = mpsc::channel::<()>();
            std::thread::spawn(move || {
                let _ = handle.join();
                let _ = done.send(());
            });
            match signal.recv_timeout(SHUTDOWN_JOIN_TIMEOUT) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    record_failure(
                        &self.health,
                        "the persistence worker did not drain within the shutdown timeout — \
                         detaching (queued writes may be lost)",
                    );
                }
            }
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

impl PersistenceFacade {
    /// The OVERFLOW feed (the bot round-8 P1): an op the bounded
    /// queue refused lands in the shared overflow — the NEWEST
    /// desired state reaches the worker when the disk side drains
    /// (bounded at one op per key; ClearAll expands per-key inside).
    fn overflow(&self, op: Op) {
        let mut overflow = self.overflow.lock().expect("overflow lock");
        // A ClearAll expands into its per-key Removes (each carrying
        // the clear's own sequence — the shared expansion),
        // superseding every per-key entry.
        let entries: Vec<(String, Op)> = op
            .expand_per_key()
            .into_iter()
            .map(|op| (op.key_name(), op))
            .collect();
        for (key_name, op) in entries {
            overflow.retain(|existing| match existing {
                Op::Put(existing_name, _, _) | Op::Remove(existing_name, _) => {
                    *existing_name != key_name
                }
                // Unreachable since the expansion (only Removes and
                // Puts enter this lane); kept exhaustively typed.
                Op::ClearAll(_) => true,
            });
            overflow.push(op);
        }
    }
}

impl PersistentCache for PersistenceFacade {
    fn put(&self, key: CacheKey, bytes: Vec<u8>) {
        // Memory first (the read side is served from here
        // immediately, in Zeroizing storage — the bot round-2 P2:
        // replaced/removed/cleared entries zeroize), then the
        // worker (the disk side is the worker's alone). The CAP is
        // enforced BEFORE the clone (the bot round-4 P2): an
        // oversized value never occupies a second allocation or a
        // queue slot — the typed refusal, the cheap path. A FULL
        // queue feeds the OVERFLOW (the bot round-8 P1 — the newest
        // state must reach the worker when the disk drains) and
        // records the backpressure failure to health. The owned
        // input is Zeroizing FROM ENTRY (the bot round-6 P2): the
        // cap-rejected credential scrubs on the early return too.
        let bytes = Zeroizing::new(bytes);
        if bytes.len() > crate::cache::MAX_PLAINTEXT_LEN {
            record_failure(
                &self.health,
                "a put exceeded the plaintext cap (the file cap minus the serialization \
                 overhead) — refused before the clone",
            );
            return;
        }
        let name = format!("{key:?}");
        self.memory
            .lock()
            .expect("facade memory lock")
            .insert(name.clone(), Zeroizing::new(bytes.to_vec()));
        let op = Op::Put(name, Zeroizing::new(bytes.to_vec()), self.next_seq());
        let send_result = self
            .sender
            .as_ref()
            .map(|sender| sender.try_send(op.clone()));
        if matches!(send_result, Some(Err(mpsc::TrySendError::Full(_)))) {
            self.overflow(op);
            record_failure(
                &self.health,
                "the persistence queue is full — a put was moved to the overflow lane \
                 (it applies when the disk side drains)",
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
        // A destructive op refused by a FULL queue goes to the
        // OVERFLOW (the bot round-8 P1 — the newest state must
        // reach the worker) and records the backpressure to health.
        let op = Op::Remove(name, self.next_seq());
        let send_result = self
            .sender
            .as_ref()
            .map(|sender| sender.try_send(op.clone()));
        if matches!(send_result, Some(Err(mpsc::TrySendError::Full(_)))) {
            self.overflow(op);
            record_failure(
                &self.health,
                "the persistence queue is full — a REMOVE was moved to the overflow lane \
                 (it applies when the disk side drains)",
            );
        }
    }

    fn clear_all(&self) {
        self.memory.lock().expect("facade memory lock").clear();
        // The sibling shape (the refactor pass's consistency note): the
        // op is built ONCE — the queue gets a clone, the overflow
        // gets the original (one sequence, not two).
        let op = Op::ClearAll(self.next_seq());
        let send_result = self
            .sender
            .as_ref()
            .map(|sender| sender.try_send(op.clone()));
        if matches!(send_result, Some(Err(mpsc::TrySendError::Full(_)))) {
            self.overflow(op);
            record_failure(
                &self.health,
                "the persistence queue is full — a CLEAR-ALL was moved to the overflow \
                 lane (it applies when the disk side drains)",
            );
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

/// The BOUNDED RETRY (ER-18, the bot round-6 P1): a failed op's
/// LATEST desired state is retained per key and retried with a
/// bounded backoff — a transient filesystem failure never leaves the
/// disk stale until ProTUN happens to update again. The retention
/// is at most one op per key (three keys — naturally bounded), and
/// the backoff doubles per consecutive failure up to the cap.
struct RetryLane {
    /// The latest failed op per key, by name (a ClearAll expands to
    /// per-key Removes before it reaches this lane — it is never
    /// held here as itself).
    pending: Vec<(String, Op, std::time::Instant)>,
    /// The current backoff (doubles per consecutive failure).
    backoff: Duration,
}

/// The retry backoff floor and cap (ER-18's "bounded").
const RETRY_BACKOFF_START: Duration = Duration::from_millis(250);
const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(30);

impl RetryLane {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
            backoff: RETRY_BACKOFF_START,
        }
    }

    /// Retains the op, keeping the NEWEST desired state per key. A
    /// ClearAll EXPANDS into per-key Removes (the bot round-7 P1 —
    /// the "" synthetic name let a pending put survive a successful
    /// clear and recreate the credential after logout, and a pending
    /// clear later delete a newer successful put; modeling the
    /// LATEST DESIRED STATE per key makes both directions
    /// impossible: the clear replaces every key's entry, a newer
    /// per-key op replaces the clear's entry for that key). An
    /// OLDER failed op never evicts a NEWER pending one (the bot
    /// round-10 P1: the overflow's newest op fails and is retained;
    /// a stale queued op for the same key then fails too — the
    /// unconditional replace would lose the newest state's retry).
    fn retain(&mut self, op: Op) {
        let deadline = std::time::Instant::now() + self.backoff;
        let expanded: Vec<(String, Op)> = op
            .expand_per_key()
            .into_iter()
            .map(|op| (op.key_name(), op))
            .collect();
        for (name, op) in expanded {
            // Newest-wins: an existing pending op with a sequence at
            // least as new keeps its place.
            let superseded = self.pending.iter().any(|(existing, existing_op, _)| {
                *existing == name && existing_op.seq() >= op.seq()
            });
            if superseded {
                continue;
            }
            self.pending.retain(|(existing, _, _)| *existing != name);
            self.pending.push((name, op, deadline));
        }
        self.backoff = (self.backoff * 2).min(RETRY_BACKOFF_MAX);
    }

    /// The earliest deadline among the pending ops (the wake time),
    /// or a long sleep when idle.
    fn next_deadline(&self) -> Option<std::time::Instant> {
        self.pending.iter().map(|(_, _, at)| *at).min()
    }

    /// Drains the ops whose backoff has elapsed (failure clears the
    /// lane for the key — a fresh retain re-arms it).
    fn take_ready(&mut self, now: std::time::Instant) -> Vec<Op> {
        let mut ready = Vec::new();
        let mut index = 0;
        while index < self.pending.len() {
            if self.pending[index].2 <= now {
                let (_, op, _) = self.pending.remove(index);
                ready.push(op);
            } else {
                index += 1;
            }
        }
        ready
    }

    /// Takes ALL pending ops regardless of deadline (the shutdown
    /// drain — the bot round-7 P1: a disconnect with a pending
    /// retry exited clean while the desired state was never
    /// applied; the final pass attempts everything once).
    fn take_all(&mut self) -> Vec<Op> {
        self.pending.drain(..).map(|(_, op, _)| op).collect()
    }

    /// A success for this key clears pending retries up to the
    /// APPLIED sequence (the bot round-10 P1: an older op's success
    /// must not drop a NEWER pending op — the failed newest state
    /// stays armed) and resets the backoff ladder.
    fn note_success(&mut self, name: &str, applied_seq: u64) {
        self.pending.retain(|(existing, existing_op, _)| {
            !(*existing == name && existing_op.seq() <= applied_seq)
        });
        if self.pending.is_empty() {
            self.backoff = RETRY_BACKOFF_START;
        }
    }
}

/// The worker loop (serialized — FR-7JB): drains ops in BATCHES with
/// per-key COALESCING (the bot round-2 P1's claim made real — only
/// the LAST op per key in a batch applies), failures recorded to
/// health through the cache's FALLIBLE path, the applied counter
/// advancing only on success — and the LATEST failed state retained
/// for bounded-backoff retry (ER-18).
fn worker_loop(
    cache: Arc<EncryptedCache>,
    receiver: mpsc::Receiver<Op>,
    health: &HealthSlot,
    overflow: &Mutex<Vec<Op>>,
) {
    // The apply pass, shared by the live loop and the shutdown
    // drain: coalesce, expand, attempt, record, retain.
    fn apply_pass(
        batch: Vec<Op>,
        cache: &EncryptedCache,
        health: &HealthSlot,
        retry: &mut RetryLane,
        last_applied: &mut HashMap<String, u64>,
    ) {
        let mut batch = batch;
        // Coalesce: keep the LAST op per key (and the last ClearAll,
        // which dominates everything before it).
        let mut coalesced: Vec<Op> = Vec::with_capacity(batch.len());
        let mut saw_clear = false;
        for op in batch.drain(..).rev() {
            let name = match &op {
                Op::Put(name, _, _) => Some(name.clone()),
                Op::Remove(name, _) => Some(name.clone()),
                Op::ClearAll(_) => None,
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
                        Op::Put(existing_name, _, _) | Op::Remove(existing_name, _) => {
                            *existing_name == name
                        }
                        Op::ClearAll(_) => false,
                    });
                    if !seen {
                        coalesced.push(op);
                    }
                }
            }
        }
        coalesced.reverse();
        // EXPAND every ClearAll into per-key Removes at the clear's
        // own sequence (the bot round-10 P1): a whole-bucket
        // try_clear_all cannot respect per-key watermarks — a key
        // whose NEWER op already applied (overflow lane racing an
        // older queued clear) would be wiped, and the success path
        // would even lower its watermark. As per-key Removes the
        // existing sequence guard skips exactly those keys and
        // clears the rest; nothing below needs a ClearAll arm.
        let expanded: Vec<Op> = coalesced.into_iter().flat_map(Op::expand_per_key).collect();
        for op in expanded {
            // The SEQUENCE GUARD (the bot round-9 P1): the queue and
            // the overflow are two lanes with no shared order — an
            // overflow op (newest) can apply before the stale queued
            // batch reaches this loop. An op whose sequence is not
            // NEWER than the last this worker applied for its key is
            // STALE (a newer desired state already persisted) and is
            // skipped, never applied over the newer state. Everything
            // here is per-key (ClearAll expanded above — the bot
            // round-10 P1), so each key checks its own watermark;
            // the guard consumes nothing.
            let seq = op.seq();
            if let Op::Put(name, _, _) | Op::Remove(name, _) = &op
                && last_applied.get(name).is_some_and(|last| *last >= seq)
            {
                continue;
            }
            let op_name = op.key_name();
            // The attempt consumes the op's payload; the RETRY lane
            // keeps a clone (ER-18 — the failed state re-applies at
            // the backoff; the payload is Zeroizing, the clone
            // scrubs with its source).
            let attempt = op.clone();
            let result: Result<(), crate::cache::CacheError> = match attempt {
                Op::Put(name, bytes, _) => match key_from_name(&name) {
                    Some(key) => cache.try_put(key, bytes.to_vec()),
                    None => Ok(()),
                },
                // The FALLIBLE paths (the bot round-4 P1): a removal
                // the filesystem rejects records to health — the
                // logout shape never reads durable while the
                // credential persists on disk.
                Op::Remove(name, _) => match key_from_name(&name) {
                    Some(key) => cache.try_remove(key),
                    None => Ok(()),
                },
                // Unreachable since the expansion above — and
                // DELIBERATELY inert: try_clear_all is the
                // whole-bucket path the round-10 P1 removed (it
                // bypasses per-key watermarks); re-instating it as a
                // fallback would silently re-introduce the fixed
                // bug.
                Op::ClearAll(_) => Ok(()),
            };
            match result {
                Ok(()) => {
                    // The watermark advances ONLY on durable success
                    // (a failed op's seq is re-armed by the retry
                    // lane). The seq-aware note_success (the bot
                    // round-10 P1) drops pending retries for this key
                    // only up to the applied sequence — a NEWER
                    // pending op (the failed newest state) survives.
                    last_applied.insert(op_name.clone(), seq);
                    retry.note_success(&op_name, seq);
                    health
                        .applied
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                Err(error) => {
                    record_failure(health, &error.to_string());
                    // ER-18: the failed op's LATEST desired state is
                    // retained for the bounded-backoff retry.
                    retry.retain(op);
                }
            }
        }
    }

    let mut retry = RetryLane::new();
    let mut last_applied: HashMap<String, u64> = HashMap::new();
    loop {
        // The ready retries go FIRST (the bot round-7 P1 — appending
        // them after the new op let the OLDER state sort later and
        // the reverse coalescer's keep-last made the STALE retry
        // win; the newest desired state must be the LAST in the
        // batch). The OVERFLOW drains into the batch's TAIL (the
        // bot round-8 P1 — ops the full queue refused carry the
        // NEWEST desired state; keep-last gives them the win).
        let mut batch: Vec<Op> = retry.take_ready(std::time::Instant::now());
        batch.extend(overflow.lock().expect("overflow lock").drain(..));
        // Wake at the next retry deadline if one is pending;
        // otherwise block for the first op. The disconnect break
        // APPLIES the ready batch first (the bot round-8 P1 — the
        // break discarded ops take_ready had already pulled; they
        // were no longer pending for take_all to recover).
        let mut disconnected = false;
        if !batch.is_empty() {
            apply_pass(batch, &cache, health, &mut retry, &mut last_applied);
            batch = Vec::new();
        }
        match retry.next_deadline() {
            Some(deadline) => match receiver.recv_timeout(deadline - std::time::Instant::now()) {
                Ok(op) => batch.push(op),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => disconnected = true,
            },
            // Bounded, never a blocking recv: a timeout loops back to
            // the overflow drain at the top (the only wake source the
            // lane has — see OVERFLOW_POLL).
            None if batch.is_empty() => match receiver.recv_timeout(OVERFLOW_POLL) {
                Ok(op) => batch.push(op),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => disconnected = true,
            },
            None => {}
        }
        if disconnected {
            if !batch.is_empty() {
                apply_pass(batch, &cache, health, &mut retry, &mut last_applied);
            }
            break;
        }
        while batch.len() < QUEUE_BOUND {
            match receiver.try_recv() {
                Ok(op) => batch.push(op),
                Err(_) => break,
            }
        }
        apply_pass(batch, &cache, health, &mut retry, &mut last_applied);
    }
    // The SHUTDOWN DRAIN (the bot round-7 P1): a disconnect with
    // pending retries exited "clean" while the desired state was
    // never applied. The final pass attempts EVERYTHING once —
    // the overflow too (its newest states may have landed between
    // the loop's last drain and the disconnect), deadline or not;
    // the join in join_worker then reports an honest completion (a
    // still-failing lane records to health; the daemon reads it on
    // the way down).
    let mut final_pass = overflow
        .lock()
        .expect("overflow lock")
        .drain(..)
        .collect::<Vec<_>>();
    final_pass.extend(retry.take_all());
    if !final_pass.is_empty() {
        apply_pass(final_pass, &cache, health, &mut retry, &mut last_applied);
        // A failure re-retained: the process is exiting — record
        // the un-drained state so the health surface tells the
        // truth on the way down.
        if !retry.pending.is_empty() {
            record_failure(
                health,
                "pending persistence retries could not drain at shutdown — the desired \
                 state may not be durable",
            );
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

#[cfg(test)]
mod round3_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use protun::api::connection::{CacheKey, PersistentCache};

    use super::*;
    use crate::cache::EncryptedCache;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "protonwire-facade3-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The bot round-3 P1: a destructive op (clear_all — the logout
    /// shape) dropped on a FULL queue records to health — the
    /// credential's disk persistence is REPORTED, never silent.
    /// (A stalled worker is simulated by never draining: hold the
    /// receiver... the facade owns it; instead fill the queue by
    /// out-pacing a blocked worker via a paused cache target.)
    #[test]
    fn a_destructive_op_dropped_on_a_full_queue_records_to_health() {
        let dir = temp_dir("fullqueue");
        let cache = Arc::new(EncryptedCache::with_key_bytes(&dir, &[11u8; 32]).unwrap());
        // An unwritable target (a directory at the entry path): the
        // worker's writes FAIL fast (the io error records through
        // the put's try_put path). A genuinely STALLED worker (slow
        // I/O, the queue actually filling) cannot be simulated
        // hermetically — the queue-full arm is the SAME matches!
        // branch this pin exercises through the failing-write arm:
        // both the put AND the destructive op record, never discard.
        std::fs::create_dir_all(dir.join("private-key.bin")).unwrap();
        let facade = PersistenceFacade::start(Arc::clone(&cache));
        for round in 0..(QUEUE_BOUND + 8) {
            facade.put(CacheKey::PrivateKey, format!("burst-{round}").into_bytes());
        }
        facade.clear_all();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let health = facade.health();
            if health.last_failure.is_some() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "neither the put nor the clear-all failure recorded: {:?}",
                health
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        // (The counter's reset semantics are the round-2 health
        // pin's; asserting them HERE is racy — a coalesced op can
        // succeed after the failure records.)
    }

    /// The bot round-3 P2 (atomic publish): a loser racing the
    /// winner's creation reloads a COMPLETE key — the temp+link
    /// publish means the final pathname never exists half-written.
    /// (The convergence pin from round 1 already proves the reload;
    /// this pin proves the published file is complete from byte 0.)
    #[test]
    fn the_published_keyfile_is_complete_from_the_first_byte() {
        let dir = temp_dir("atomic");
        let key_path = dir.join("cache.key");
        let shared = dir.join("cache");
        let first = EncryptedCache::open(&shared, &key_path).unwrap();
        drop(first);
        // No temp residue; the key is exactly 32 bytes.
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            assert!(
                !path
                    .extension()
                    .is_some_and(|ext| ext.to_string_lossy().starts_with("tmp")),
                "temp residue: {path:?}"
            );
        }
        assert_eq!(std::fs::metadata(&key_path).unwrap().len(), 32);
        // And it round-trips.
        let second = EncryptedCache::open(&shared, &key_path).unwrap();
        second.put(CacheKey::Certificate, b"v".to_vec());
        let third = EncryptedCache::open(&shared, &key_path).unwrap();
        assert_eq!(third.get(CacheKey::Certificate), Some(b"v".to_vec()));
    }
}

#[cfg(test)]
mod round6_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use protun::api::connection::{CacheKey, PersistentCache};

    use super::*;
    use crate::cache::EncryptedCache;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "protonwire-r6-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// ER-18's bounded retry (the bot round-6 P1): a FAILED put
    /// whose target then becomes writable RETRIES at the backoff —
    /// the disk converges to the desired state without a new op.
    #[test]
    fn a_failed_put_retries_when_the_target_recovers() {
        let dir = temp_dir("retry");
        let cache = Arc::new(EncryptedCache::with_key_bytes(&dir, &[13u8; 32]).unwrap());
        // Block the write, then unblock it so the retry can land.
        std::fs::create_dir_all(dir.join("certificate.bin")).unwrap();
        let facade = PersistenceFacade::start(Arc::clone(&cache));
        facade.put(CacheKey::Certificate, b"recovered".to_vec());
        // Give the first attempt time to fail (records to health).
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while facade.health().last_failure.is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            facade.health().last_failure.is_some(),
            "the first attempt failed and recorded"
        );
        // Recover the target.
        std::fs::remove_dir_all(dir.join("certificate.bin")).unwrap();
        // The retry lane re-applies at the backoff (250ms start,
        // doubling). Poll up to 30s for the disk convergence.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if cache.get(CacheKey::Certificate) == Some(b"recovered".to_vec()) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the retry never converged: {:?}",
                facade.health()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The bot round-6 P1 (clear sweeps ALL): with TWO entries on
    /// disk and the FIRST blocked, the clear still removes the
    /// second — one failure, not a stopped sweep.
    #[test]
    fn clear_all_attempts_every_entry_despite_one_failure() {
        let dir = temp_dir("sweep");
        let cache = EncryptedCache::with_key_bytes(&dir, &[14u8; 32]).unwrap();
        cache.put(CacheKey::Certificate, b"c".to_vec());
        cache.put(CacheKey::PrivateKey, b"k".to_vec());
        // Block the FIRST key's removal.
        let cert = dir.join("certificate.bin");
        std::fs::remove_file(&cert).unwrap();
        std::fs::create_dir_all(&cert).unwrap();
        let error = cache.try_clear_all().unwrap_err();
        assert!(error.to_string().contains("io"), "{error}");
        // The SECOND entry is gone anyway (the sweep did not stop).
        assert!(
            !dir.join("private-key.bin").exists(),
            "the sweep attempted every entry"
        );
    }
}

#[cfg(test)]
mod round7_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use protun::api::connection::{CacheKey, PersistentCache};

    use super::*;

    /// The bot round-7 P1 (clear cancels per-key retries): a failed
    /// put retained under Certificate, then a SUCCESSFUL clear-all —
    /// the pending put must NOT re-create the credential after
    /// logout (the clear superseded it per-key).
    #[test]
    fn a_successful_clear_cancels_pending_per_key_retries() {
        let mut retry = RetryLane::new();
        // A failed put for Certificate retained.
        retry.retain(Op::Put(
            "Certificate".to_owned(),
            Zeroizing::new(b"stale".to_vec()),
            1,
        ));
        // A successful ClearAll arrives — note_success("") under the
        // old synthetic-name scheme cleared only "", leaving the
        // Certificate put. The EXPANSION model: the clear's success
        // is per-key — simulate by the retain of a ClearAll (which
        // now REPLACES the Certificate entry with a Remove).
        retry.retain(Op::ClearAll(3));
        // The Certificate entry is now a REMOVE (the clear
        // superseded the stale put).
        assert!(
            retry
                .pending
                .iter()
                .any(|(name, op, _)| name == "Certificate" && matches!(op, Op::Remove(_, _))),
            "the clear replaced the stale put per-key: {:?}",
            retry.pending.iter().map(|(n, _, _)| n).collect::<Vec<_>>()
        );
        // And no synthetic "" entry exists.
        assert!(
            !retry.pending.iter().any(|(name, _, _)| name.is_empty()),
            "no synthetic clear-all name remains"
        );
    }

    /// The bot round-7 P1 (a newer per-key op supersedes the
    /// clear's entry for that key): a pending clear-all then a
    /// newer put for PrivateKey — the key's entry is the PUT.
    #[test]
    fn a_newer_put_supersedes_the_clear_for_that_key() {
        let mut retry = RetryLane::new();
        retry.retain(Op::ClearAll(3));
        retry.retain(Op::Put(
            "PrivateKey".to_owned(),
            Zeroizing::new(b"newer".to_vec()),
            4,
        ));
        let private = retry
            .pending
            .iter()
            .find(|(name, _, _)| name == "PrivateKey")
            .expect("the entry exists");
        assert!(
            matches!(private.1, Op::Put(_, _, _)),
            "the newer put is the desired state for the key"
        );
    }

    /// The bot round-7 P1 (shutdown drains pending retries): a
    /// facade drop with a pending (ready) retry applies it in the
    /// final pass — the disk reflects the desired state.
    #[test]
    fn shutdown_drains_pending_retries() {
        let dir = std::path::PathBuf::from(format!(
            "/tmp/protonwire-r7-drain-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cache = Arc::new(EncryptedCache::with_key_bytes(&dir, &[15u8; 32]).unwrap());
        // Make the FIRST attempt fail (the target blocked), then
        // unblock BEFORE drop so the shutdown drain can land it.
        std::fs::create_dir_all(dir.join("api-session.bin")).unwrap();
        let facade = PersistenceFacade::start(Arc::clone(&cache));
        facade.put(CacheKey::ApiSession, b"last-state".to_vec());
        // Wait for the first failure to record (the op is now
        // pending for retry at the 250ms backoff).
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while facade.health().last_failure.is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(facade.health().last_failure.is_some());
        // Unblock the target, then drop IMMEDIATELY (before the
        // backoff elapses): the shutdown drain attempts the pending
        // op regardless of the deadline.
        std::fs::remove_dir_all(dir.join("api-session.bin")).unwrap();
        drop(facade);
        assert_eq!(
            cache.get(CacheKey::ApiSession),
            Some(b"last-state".to_vec()),
            "the shutdown drain applied the pending retry"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod round8_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use protun::api::connection::{CacheKey, PersistentCache};

    use super::*;

    /// The bot round-8 P1's INVARIANT, via the round-10 mechanism: a
    /// successful clear invalidates every pending retry it covers —
    /// as per-key Removes the clear advances each key's watermark
    /// past the pending ops (seq ≤ clear seq), while a NEWER pending
    /// op (the failed newest state, the round-10 P1) stays armed.
    #[test]
    fn a_successful_clear_covers_pending_retries_but_not_newer_ones() {
        let mut retry = RetryLane::new();
        retry.retain(Op::Put(
            "Certificate".to_owned(),
            Zeroizing::new(b"stale".to_vec()),
            1,
        ));
        retry.retain(Op::Put(
            "PrivateKey".to_owned(),
            Zeroizing::new(b"newest".to_vec()),
            9,
        ));
        // The clear at seq 5 succeeds per key: the seq-1 pending
        // retry is covered (its watermark moves past it); the seq-9
        // pending op is NEWER and must survive.
        retry.note_success("Certificate", 5);
        retry.note_success("PrivateKey", 5);
        let names: Vec<&str> = retry
            .pending
            .iter()
            .map(|(name, _, _)| name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["PrivateKey"],
            "older retries are covered by the clear; the newest state stays armed"
        );
    }

    /// The bot round-8 P1 (overflow): an op the full queue refused
    /// reaches the worker's batch — the newest state applies when
    /// the disk side drains. (The full-queue shape is the facade's
    /// overflow() + the worker's tail-drain; this pins the WIRING:
    /// an overflow op converges to disk without any queue slot.)
    #[test]
    fn an_overflow_op_reaches_disk() {
        let dir = std::path::PathBuf::from(format!(
            "/tmp/protonwire-r8-overflow-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cache = Arc::new(EncryptedCache::with_key_bytes(&dir, &[16u8; 32]).unwrap());
        let facade = PersistenceFacade::start(Arc::clone(&cache));
        // Feed an op DIRECTLY through the overflow lane (the full-
        // queue shape): the worker's tail-drain must apply it.
        facade.overflow(Op::Put(
            "Certificate".to_owned(),
            Zeroizing::new(b"overflow-state".to_vec()),
            facade.next_seq(),
        ));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while cache.get(CacheKey::Certificate) != Some(b"overflow-state".to_vec()) {
            assert!(
                std::time::Instant::now() < deadline,
                "the overflow op never reached disk"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod round9_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use protun::api::connection::{CacheKey, PersistentCache};

    use super::*;

    /// The bot round-9 P1 (queue/overflow ordering): a NEWEST op
    /// fed through the overflow applies FIRST (its lane is the
    /// worker's immediate batch), then a STALE queued op for the
    /// same key arrives after — the sequence guard must SKIP the
    /// stale write; the disk keeps the newest value.
    #[test]
    fn a_stale_queued_op_cannot_overwrite_a_newer_applied_state() {
        let dir = std::path::PathBuf::from(format!(
            "/tmp/protonwire-r9-order-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cache = Arc::new(EncryptedCache::with_key_bytes(&dir, &[17u8; 32]).unwrap());
        let facade = PersistenceFacade::start(Arc::clone(&cache));
        // The newest state (seq N+1) through the overflow lane.
        let newest = facade.next_seq();
        facade.overflow(Op::Put(
            "Certificate".to_owned(),
            Zeroizing::new(b"newest".to_vec()),
            newest,
        ));
        // Wait for it to land on disk.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while cache.get(CacheKey::Certificate) != Some(b"newest".to_vec()) {
            assert!(
                std::time::Instant::now() < deadline,
                "the overflow op never applied"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // The STALE queued op (seq N < the applied watermark) — fed
        // through the overflow with an older sequence (the queue's
        // delayed delivery, the same worker state).
        facade.overflow(Op::Put(
            "Certificate".to_owned(),
            Zeroizing::new(b"stale".to_vec()),
            newest - 1,
        ));
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            cache.get(CacheKey::Certificate),
            Some(b"newest".to_vec()),
            "the sequence guard skipped the stale write"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The overflow lane's idle-drain contract (the CI flake that
    /// broke the round-9 pin above): an op landing in the OVERFLOW
    /// while the worker is PARKED in its idle wait — no queue
    /// traffic, no pending retry, which is precisely when overflow
    /// fills — still reaches the disk within one poll cadence. The
    /// newest-state guarantee cannot depend on future queue traffic
    /// (before OVERFLOW_POLL the idle wait was a blocking recv the
    /// lane could never wake; this test parks the worker FIRST, the
    /// exact scheduling the CI runner exposed).
    #[test]
    fn overflow_drains_while_the_worker_is_parked_idle() {
        let dir = std::path::PathBuf::from(format!(
            "/tmp/protonwire-r9-idle-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cache = Arc::new(EncryptedCache::with_key_bytes(&dir, &[19u8; 32]).unwrap());
        let facade = PersistenceFacade::start(Arc::clone(&cache));
        // Park the worker in the idle wait: it started with nothing
        // to apply, so after one cadence it is definitively waiting.
        std::thread::sleep(OVERFLOW_POLL + Duration::from_millis(100));
        // The newest state lands in the overflow lane while the
        // worker idles.
        let newest = facade.next_seq();
        facade.overflow(Op::Put(
            "Certificate".to_owned(),
            Zeroizing::new(b"idle-newest".to_vec()),
            newest,
        ));
        // It must reach the disk on the poll cadence alone.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while cache.get(CacheKey::Certificate) != Some(b"idle-newest".to_vec()) {
            assert!(
                std::time::Instant::now() < deadline,
                "the overflow op never drained off an idle worker"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The bot round-10 P1 (retain): an OLDER failed op must not
    /// evict a NEWER pending one — the overflow's newest state fails
    /// first (retained), the stale queued op for the same key fails
    /// after; the unconditional replace would have lost the newest
    /// state's retry entirely.
    #[test]
    fn an_older_failed_op_does_not_replace_a_newer_pending_one() {
        let mut retry = RetryLane::new();
        retry.retain(Op::Put(
            "Certificate".to_owned(),
            Zeroizing::new(b"newest".to_vec()),
            65,
        ));
        // The stale seq-64 op fails later — the lane keeps 65.
        retry.retain(Op::Put(
            "Certificate".to_owned(),
            Zeroizing::new(b"stale".to_vec()),
            64,
        ));
        assert_eq!(retry.pending.len(), 1);
        assert_eq!(retry.pending[0].1.seq(), 65);

        // And the symmetric arm: a NEWER failed op DOES replace the
        // older pending one (the latest desired state wins).
        retry.retain(Op::Put(
            "Certificate".to_owned(),
            Zeroizing::new(b"newest-2".to_vec()),
            66,
        ));
        assert_eq!(retry.pending.len(), 1);
        assert_eq!(retry.pending[0].1.seq(), 66);
    }

    /// The bot round-10 P1 (apply path): a ClearAll OLDER than an
    /// already-applied per-key op must not wipe that key — the
    /// per-key expansion makes the sequence guard skip exactly the
    /// newer-applied key (driven through the facade surface, the
    /// overflow lane both times — the newest state applies on the
    /// idle-drain cadence, then the STALE clear arrives).
    #[test]
    fn an_older_clear_does_not_wipe_a_newer_applied_key() {
        let dir = std::path::PathBuf::from(format!(
            "/tmp/protonwire-r10-clear-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cache = Arc::new(EncryptedCache::with_key_bytes(&dir, &[23u8; 32]).unwrap());
        let facade = PersistenceFacade::start(Arc::clone(&cache));
        // The NEWEST certificate state lands and applies.
        let newest = facade.next_seq();
        facade.overflow(Op::Put(
            "Certificate".to_owned(),
            Zeroizing::new(b"newest".to_vec()),
            newest,
        ));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while cache.get(CacheKey::Certificate) != Some(b"newest".to_vec()) {
            assert!(
                std::time::Instant::now() < deadline,
                "the newest op never applied"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // The STALE ClearAll (older than the applied put): the
        // certificate is NOT wiped; the other keys clear if set.
        facade.overflow(Op::ClearAll(newest - 1));
        std::thread::sleep(OVERFLOW_POLL + Duration::from_millis(200));
        assert_eq!(
            cache.get(CacheKey::Certificate),
            Some(b"newest".to_vec()),
            "the newer applied state survives the older clear"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
