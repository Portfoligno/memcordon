//! Low-frequency inventory cost evidence; never part of the input identity.
//! Costs sum across workers and may exceed wall time; active entries include
//! traversal plus at most four native readers in the production inventory.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub enum Operation {
    Metadata,
    Canonicalize,
    Directory,
    Symlink,
    Access,
    Open,
    ReadHash,
}

const OPERATIONS: [Operation; 7] = [
    Operation::Metadata,
    Operation::Canonicalize,
    Operation::Directory,
    Operation::Symlink,
    Operation::Access,
    Operation::Open,
    Operation::ReadHash,
];

#[derive(Default)]
struct State {
    stopped: bool,
    active: Vec<(thread::ThreadId, Operation, PathBuf, Instant)>,
    counts: [u64; OPERATIONS.len()],
    costs: [Duration; OPERATIONS.len()],
}

struct Shared {
    root: PathBuf,
    started: Instant,
    state: Mutex<State>,
    wake: Condvar,
    bytes: AtomicU64,
    read_calls: AtomicU64,
    read_ns: AtomicU64,
    hash_ns: AtomicU64,
}

impl Shared {
    fn snapshot(&self) -> String {
        let state = self
            .state
            .lock()
            .expect("inventory progress state poisoned");
        let costs = OPERATIONS
            .iter()
            .enumerate()
            .map(|(index, operation)| {
                format!(
                    "{operation:?}_count={} {operation:?}_ms={}",
                    state.counts[index],
                    state.costs[index].as_millis()
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let active = state
            .active
            .iter()
            .map(|(_, operation, path, started)| {
                format!(
                    "operation={operation:?} path={path:?} operation_ms={}",
                    started.elapsed().as_millis()
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let active = if active.is_empty() {
            "operation=idle"
        } else {
            &active
        };
        format!(
            "root={:?} elapsed_ms={} {costs} bytes={} read_calls={} read_ms={} hash_ms={} {active}",
            self.root,
            self.started.elapsed().as_millis(),
            self.bytes.load(Ordering::Relaxed),
            self.read_calls.load(Ordering::Relaxed),
            self.read_ns.load(Ordering::Relaxed) / 1_000_000,
            self.hash_ns.load(Ordering::Relaxed) / 1_000_000
        )
    }
}

pub struct InventoryProgress {
    shared: Arc<Shared>,
    observer: Option<JoinHandle<()>>,
}

impl InventoryProgress {
    pub fn worker(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            observer: None,
        }
    }
    pub fn new(root: &Path) -> Self {
        Self::new_with_interval(root, Duration::from_secs(30))
    }

    /// Explicit cadence permits bounded observer tests without environment controls.
    pub fn new_with_interval(root: &Path, interval: Duration) -> Self {
        assert!(
            !interval.is_zero(),
            "inventory progress interval must be positive"
        );
        let shared = Arc::new(Shared {
            root: root.to_path_buf(),
            started: Instant::now(),
            state: Mutex::new(State::default()),
            wake: Condvar::new(),
            bytes: AtomicU64::new(0),
            read_calls: AtomicU64::new(0),
            read_ns: AtomicU64::new(0),
            hash_ns: AtomicU64::new(0),
        });
        let observer_state = Arc::clone(&shared);
        let observer = thread::spawn(move || {
            loop {
                let state = observer_state
                    .state
                    .lock()
                    .expect("inventory progress state poisoned");
                let (state, _) = observer_state
                    .wake
                    .wait_timeout_while(state, interval, |state| !state.stopped)
                    .expect("inventory progress state poisoned");
                if state.stopped {
                    break;
                }
                drop(state);
                eprintln!("[native inventory] progress {}", observer_state.snapshot());
            }
        });
        Self {
            shared,
            observer: Some(observer),
        }
    }

    pub fn run<T, E>(
        &self,
        operation: Operation,
        path: &Path,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let started = Instant::now();
        {
            let mut state = self
                .shared
                .state
                .lock()
                .expect("inventory progress state poisoned");
            let id = thread::current().id();
            assert!(
                !state.active.iter().any(|entry| entry.0 == id),
                "inventory operations must not nest"
            );
            state
                .active
                .push((id, operation, path.to_path_buf(), started));
        }
        let result = action();
        let mut state = self
            .shared
            .state
            .lock()
            .expect("inventory progress state poisoned");
        state.counts[operation as usize] += 1;
        state.costs[operation as usize] += started.elapsed();
        state
            .active
            .retain(|entry| entry.0 != thread::current().id());
        result
    }

    /// Chunk counters use atomics, never the observer mutex or filesystem calls.
    pub fn record_chunk(&self, read: Duration, hash: Duration, bytes: u64) {
        self.shared.read_calls.fetch_add(1, Ordering::Relaxed);
        self.shared.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.shared.read_ns.fetch_add(
            read.as_nanos().try_into().unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.shared.hash_ns.fetch_add(
            hash.as_nanos().try_into().unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    pub fn snapshot(&self) -> String {
        self.shared.snapshot()
    }

    pub fn finish(&mut self, success: bool) {
        self.stop();
        eprintln!(
            "[native inventory] {} {}",
            if success { "complete" } else { "failed" },
            self.snapshot()
        );
    }

    fn stop(&mut self) {
        if self.observer.is_none() {
            return;
        }
        self.shared
            .state
            .lock()
            .expect("inventory progress state poisoned")
            .stopped = true;
        self.shared.wake.notify_all();
        if let Some(observer) = self.observer.take() {
            observer
                .join()
                .expect("inventory progress observer panicked");
        }
    }
}

impl Drop for InventoryProgress {
    fn drop(&mut self) {
        self.stop();
    }
}
