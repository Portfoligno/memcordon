//! Completion-driven reads keep native resources bounded without batch barriers.
use std::io;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};

pub const WORKERS: usize = 4;

pub struct InventoryWorkers<T, R> {
    sender: Option<mpsc::SyncSender<(usize, T)>>,
    results: mpsc::Receiver<(usize, Result<R, String>)>,
    workers: Vec<JoinHandle<()>>,
    pending: usize,
}

impl<T: Send + 'static, R: Send + 'static> InventoryWorkers<T, R> {
    pub fn new(action: impl Fn(T, &mut [u8]) -> R + Send + Sync + 'static) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<(usize, T)>(WORKERS);
        let (results, received) = mpsc::sync_channel(WORKERS);
        let receiver = Arc::new(Mutex::new(receiver));
        let action = Arc::new(action);
        let mut pool = Self {
            sender: Some(sender),
            results: received,
            workers: Vec::new(),
            pending: 0,
        };
        for _ in 0..WORKERS {
            let receiver = Arc::clone(&receiver);
            let action = Arc::clone(&action);
            let results = results.clone();
            pool.workers.push(thread::Builder::new().spawn(move || {
                let mut buffer = vec![0; crate::inventory_reader::BUFFER_SIZE];
                loop {
                    let task = receiver
                        .lock()
                        .expect("inventory task queue poisoned")
                        .recv();
                    let Ok((index, task)) = task else {
                        break;
                    };
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        action(task, &mut buffer)
                    }))
                    .map_err(|_| "native inventory worker panicked".to_owned());
                    if results.send((index, result)).is_err() {
                        break;
                    }
                }
            })?);
        }
        Ok(pool)
    }

    /// Return one completion at capacity, leaving room to refill the freed slot.
    /// Callers place results by index; completion order is intentionally independent.
    pub fn submit(&mut self, index: usize, task: T) -> io::Result<Vec<(usize, R)>> {
        assert!(
            self.pending < WORKERS,
            "inventory batch exceeds worker bound"
        );
        self.sender
            .as_ref()
            .expect("live inventory workers")
            .send((index, task))
            .map_err(|_| io::Error::other("inventory task queue disconnected"))?;
        self.pending += 1;
        if self.pending == WORKERS {
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
        self.sender.take();
        // At most WORKERS results exist; the result queue holds all of them even
        // when traversal exits early. Joining cannot wait on an undrained queue.
        for worker in self.workers.drain(..) {
            worker
                .join()
                .expect("inventory worker terminated outside its task");
        }
    }
}
