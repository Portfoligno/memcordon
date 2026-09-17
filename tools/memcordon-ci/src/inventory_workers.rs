//! Completion-driven reads keep native resources bounded without batch barriers.
use std::io;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};

// Native inventory is dominated by filesystem latency, not hashing. Keep a
// bounded set of concurrent reads (and one reusable MiB buffer per reader).
pub const WORKERS: usize = 8;
// Allow traversal to prepare another wave while all readers are busy. Sharing
// the worker count as the admission limit otherwise stalls traversal before it
// can prepare the next file, leaving readers idle during metadata and opens.
pub const CAPACITY: usize = WORKERS * 2;

pub(crate) type Task = Box<dyn FnOnce(&mut [u8]) + Send>;
type Action<T, R> = dyn Fn(T, &mut [u8]) -> R + Send + Sync;

/// One execution budget shared by preparation and reading. Logical queues keep
/// their own admission limits and ordered results without reserving idle threads.
pub struct InventoryExecutor {
    sender: Option<mpsc::SyncSender<Task>>,
    workers: Vec<JoinHandle<()>>,
}

impl InventoryExecutor {
    pub(crate) fn submit(&self, task: Task) -> io::Result<()> {
        self.sender
            .as_ref()
            .expect("live inventory executor")
            .send(task)
            .map_err(|_| io::Error::other("inventory task queue disconnected"))
    }

    /// Reuse the existing two-stage thread, buffer, and admission budget. Either
    /// stage can use idle capacity belonging to the other; totals do not grow.
    pub fn native_pipeline() -> io::Result<Arc<Self>> {
        Self::new(WORKERS * 2, CAPACITY * 2).map(Arc::new)
    }

    fn new(workers: usize, capacity: usize) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Task>(capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut pool = Self {
            sender: Some(sender),
            workers: Vec::new(),
        };
        for _ in 0..workers {
            let receiver = Arc::clone(&receiver);
            pool.workers.push(thread::Builder::new().spawn(move || {
                let mut buffer = vec![0; crate::inventory_reader::BUFFER_SIZE];
                loop {
                    let task = receiver
                        .lock()
                        .expect("inventory task queue poisoned")
                        .recv();
                    let Ok(task) = task else {
                        break;
                    };
                    task(&mut buffer);
                }
            })?);
        }
        Ok(pool)
    }
}

impl Drop for InventoryExecutor {
    fn drop(&mut self) {
        self.sender.take();
        for worker in self.workers.drain(..) {
            worker
                .join()
                .expect("inventory worker terminated outside its task");
        }
    }
}

pub struct InventoryWorkers<T, R> {
    executor: Arc<InventoryExecutor>,
    action: Arc<Action<T, R>>,
    sender: mpsc::SyncSender<(usize, Result<R, String>)>,
    results: mpsc::Receiver<(usize, Result<R, String>)>,
    pending: usize,
}

impl<T: Send + 'static, R: Send + 'static> InventoryWorkers<T, R> {
    pub fn new(action: impl Fn(T, &mut [u8]) -> R + Send + Sync + 'static) -> io::Result<Self> {
        let executor = Arc::new(InventoryExecutor::new(WORKERS, CAPACITY)?);
        Ok(Self::with_executor(executor, action))
    }

    pub fn with_executor(
        executor: Arc<InventoryExecutor>,
        action: impl Fn(T, &mut [u8]) -> R + Send + Sync + 'static,
    ) -> Self {
        let (sender, results) = mpsc::sync_channel(CAPACITY);
        Self {
            executor,
            action: Arc::new(action),
            sender,
            results,
            pending: 0,
        }
    }

    /// Return one completion at capacity, leaving room to refill the freed slot.
    /// Callers place results by index; completion order is intentionally independent.
    pub fn submit(&mut self, index: usize, task: T) -> io::Result<Vec<(usize, R)>> {
        assert!(
            self.pending < CAPACITY,
            "inventory admission exceeds capacity"
        );
        let action = Arc::clone(&self.action);
        let results = self.sender.clone();
        self.executor
            .sender
            .as_ref()
            .expect("live inventory workers")
            .send(Box::new(move |buffer| {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(task, buffer)))
                        .map_err(|_| "native inventory worker panicked".to_owned());
                let _ = results.send((index, result));
            }))
            .map_err(|_| io::Error::other("inventory task queue disconnected"))?;
        self.pending += 1;
        if self.pending == CAPACITY {
            let (index, result) = self
                .results
                .recv()
                .map_err(|_| io::Error::other("inventory result queue disconnected"))?;
            self.pending -= 1;
            result
                .map(|value| vec![(index, value)])
                .map_err(io::Error::other)
        } else {
            Ok(Vec::new())
        }
    }

    /// Prepare an ordered batch with bounded admission, settling it completely
    /// before callers recurse into another batch using the same pool.
    pub fn map_ordered(&mut self, tasks: impl IntoIterator<Item = T>) -> io::Result<Vec<R>> {
        assert_eq!(self.pending, 0, "ordered batch requires an idle pool");
        let mut completed = Vec::new();
        for (index, task) in tasks.into_iter().enumerate() {
            completed.extend(self.submit(index, task)?);
        }
        completed.extend(self.drain()?);
        completed.sort_by_key(|entry| entry.0);
        Ok(completed.into_iter().map(|(_, result)| result).collect())
    }

    pub fn drain(&mut self) -> io::Result<Vec<(usize, R)>> {
        let mut completed = Vec::with_capacity(self.pending);
        while self.pending != 0 {
            let result = self
                .results
                .recv()
                .map_err(|_| io::Error::other("inventory result queue disconnected"))?;
            self.pending -= 1;
            completed.push(result);
        }
        completed.sort_by_key(|entry| entry.0);
        completed
            .into_iter()
            .map(|(index, result)| result.map(|value| (index, value)).map_err(io::Error::other))
            .collect()
    }
}

impl<T, R> Drop for InventoryWorkers<T, R> {
    fn drop(&mut self) {
        // Settle only this logical queue. Another stage may still own the shared
        // executor; the last owner shuts down and joins its threads.
        while self.pending != 0 {
            let _ = self
                .results
                .recv()
                .expect("inventory result queue disconnected");
            self.pending -= 1;
        }
    }
}
