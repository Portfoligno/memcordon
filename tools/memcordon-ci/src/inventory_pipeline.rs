//! Ordered traversal with bounded speculative preparation and leaf worker tasks.
//!
//! Listings and the result manifest remain proportional to the input tree. The
//! limits here bound admitted work, handles and prepared results, not total RAM.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};

use crate::inventory_progress::{TaskClass, TaskState};
use crate::inventory_workers::{CAPACITY, InventoryExecutor};
use crate::{CiError, Result};

pub const ADMISSION: usize = CAPACITY * 2;

pub struct ValidatedDigest {
    pub digest: String,
    pub bytes: u64,
}

pub enum Node<E, F, R> {
    Skip,
    Record(R),
    File(F, R),
    Expand(E),
}

/// Filesystem actions are leaf tasks: they must not enqueue dependent work or
/// access coordinator-owned traversal state. `classify` alone claims identities.
pub trait InventoryBackend: Send + Sync + 'static {
    type Entry: Send + 'static;
    type Prepared: Send + 'static;
    type Expansion: Send + 'static;
    type File: Send + 'static;
    type Record: Send + 'static;

    fn prepare(&self, entry: Self::Entry) -> Result<Self::Prepared>;
    fn classify(
        &self,
        prepared: Self::Prepared,
        visited: &mut BTreeSet<PathBuf>,
    ) -> Result<Node<Self::Expansion, Self::File, Self::Record>>;
    fn expand(&self, request: Self::Expansion) -> Result<(Vec<Self::Entry>, Self::Record)>;
    fn read(&self, request: Self::File, buffer: &mut [u8]) -> Result<ValidatedDigest>;
    fn set_digest(&self, record: &mut Self::Record, digest: ValidatedDigest);
    fn check_cancelled(&self) -> Result<()> {
        Ok(())
    }
    fn transition(&self, _id: u64, _class: TaskClass, _state: TaskState) -> Result<()> {
        Ok(())
    }
    fn observe_wait<T>(&self, _draining: bool, action: impl FnOnce() -> Result<T>) -> Result<T> {
        action()
    }
    fn task_dependency(&self, _id: u64, _parent: Option<u64>, _ordinal: Option<u64>) -> Result<()> {
        Ok(())
    }
}

enum Outcome<B: InventoryBackend> {
    Prepared(B::Prepared),
    Expanded(Vec<B::Entry>, B::Record),
    Read(ValidatedDigest),
}

struct Completion<B: InventoryBackend> {
    id: usize,
    class: TaskClass,
    result: Result<Outcome<B>>,
}

enum Frame<B: InventoryBackend> {
    Entry(B::Entry),
    Children {
        entries: VecDeque<B::Entry>,
        prepared: VecDeque<usize>,
        parent: usize,
    },
    Finish(B::Record),
}

/// One executor can serve multiple root-fenced traversals. No observer or root
/// identity is retained by the executor itself.
pub struct InventorySession {
    executor: Arc<InventoryExecutor>,
}

impl InventorySession {
    pub fn new() -> Result<Self> {
        Ok(Self {
            executor: InventoryExecutor::native_pipeline()?,
        })
    }

    pub fn measure<B: InventoryBackend>(
        &self,
        backend: B,
        root: B::Entry,
        visited: &mut BTreeSet<PathBuf>,
    ) -> Result<Vec<B::Record>> {
        let (sender, receiver) = mpsc::sync_channel(ADMISSION);
        let mut traversal = Traversal {
            executor: &self.executor,
            backend: Arc::new(backend),
            sender,
            receiver,
            next_id: 0,
            next_ordinal: 0,
            pending: 0,
            preparations: 0,
            ready: BTreeMap::new(),
            files: BTreeMap::new(),
            records: Vec::new(),
            errors: BTreeMap::new(),
        };
        let result = traversal.walk(root, visited);
        if let Err(error) = result {
            traversal
                .errors
                .entry(traversal.next_ordinal)
                .or_insert(error);
        }
        // Fence every task class even on traversal failure. Earlier admitted
        // file errors win deterministically over later traversal errors.
        let backend = Arc::clone(&traversal.backend);
        backend.observe_wait(true, || {
            while traversal.pending != 0 {
                traversal.receive_draining()?;
            }
            Ok(())
        })?;
        traversal.backend.check_cancelled()?;
        if let Some((_, error)) = traversal.errors.pop_first() {
            return Err(error);
        }
        Ok(std::mem::take(&mut traversal.records)
            .into_iter()
            .map(|record| record.expect("successful inventory has no unresolved file"))
            .collect())
    }
}

struct Traversal<'a, B: InventoryBackend> {
    executor: &'a Arc<InventoryExecutor>,
    backend: Arc<B>,
    sender: mpsc::SyncSender<Completion<B>>,
    receiver: mpsc::Receiver<Completion<B>>,
    next_id: usize,
    next_ordinal: usize,
    pending: usize,
    // Includes queued, running and received-but-not-consumed preparation.
    preparations: usize,
    ready: BTreeMap<usize, Result<Outcome<B>>>,
    files: BTreeMap<usize, (usize, usize, B::Record)>,
    records: Vec<Option<B::Record>>,
    errors: BTreeMap<usize, CiError>,
}

impl<B: InventoryBackend> Traversal<'_, B> {
    fn submit(
        &mut self,
        class: TaskClass,
        parent: Option<usize>,
        ordinal: Option<usize>,
        action: impl FnOnce(&B, &mut [u8]) -> Result<Outcome<B>> + Send + 'static,
    ) -> Result<usize> {
        self.backend.check_cancelled()?;
        while self.pending == ADMISSION {
            self.receive()?;
        }
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).expect("task id overflow");
        let backend = Arc::clone(&self.backend);
        let sender = self.sender.clone();
        self.backend
            .transition(id as u64, class, TaskState::Offered)?;
        self.backend.task_dependency(
            id as u64,
            parent.map(|value| value as u64),
            ordinal.map(|value| value as u64),
        )?;
        self.executor.submit(Box::new(move |buffer| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                backend.transition(id as u64, class, TaskState::Started)?;
                backend.check_cancelled()?;
                action(&backend, buffer)
            }))
            .unwrap_or_else(|_| Err(CiError::Message("native inventory worker panicked".into())));
            let readiness = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                backend.transition(id as u64, class, TaskState::Ready)
            }))
            .unwrap_or_else(|_| {
                Err(CiError::Message(
                    "inventory completion observer panicked".into(),
                ))
            });
            let result = readiness.and(result);
            let _ = sender.send(Completion { id, class, result });
        }))?;
        self.pending += 1;
        Ok(id)
    }

    fn apply(&mut self, completion: Completion<B>) {
        self.pending = self
            .pending
            .checked_sub(1)
            .expect("unregistered completion");
        let result = self
            .backend
            .transition(completion.id as u64, completion.class, TaskState::Received)
            .and(completion.result);
        if let Some((ordinal, index, mut record)) = self.files.remove(&completion.id) {
            match result {
                Ok(Outcome::Read(digest)) => {
                    self.backend.set_digest(&mut record, digest);
                    self.records[index] = Some(record);
                }
                Err(error) => {
                    self.errors.insert(ordinal, error);
                }
                _ => panic!("file task returned a different task kind"),
            }
        } else {
            assert!(self.ready.insert(completion.id, result).is_none());
        }
    }

    fn receive(&mut self) -> Result<()> {
        let backend = Arc::clone(&self.backend);
        let completion = backend.observe_wait(false, || {
            loop {
                backend.check_cancelled()?;
                match self
                    .receiver
                    .recv_timeout(std::time::Duration::from_millis(100))
                {
                    Ok(completion) => break Ok(completion),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        break Err(CiError::Message(
                            "inventory result queue disconnected".into(),
                        ));
                    }
                }
            }
        })?;
        self.apply(completion);
        Ok(())
    }

    fn receive_draining(&mut self) -> Result<()> {
        let completion = self
            .receiver
            .recv()
            .map_err(|_| CiError::Message("inventory result queue disconnected".into()))?;
        self.apply(completion);
        Ok(())
    }

    fn harvest(&mut self) {
        while let Ok(completion) = self.receiver.try_recv() {
            self.apply(completion);
        }
    }

    fn wait(&mut self, id: usize) -> Result<Outcome<B>> {
        loop {
            self.backend.check_cancelled()?;
            if let Some(result) = self.ready.remove(&id) {
                return result;
            }
            self.receive()?;
        }
    }

    fn prepare(&mut self, entry: B::Entry, parent: Option<usize>) -> Result<usize> {
        assert!(self.preparations < CAPACITY, "preparation window exceeded");
        let id = self.submit(TaskClass::Prepare, parent, None, move |backend, _| {
            backend.prepare(entry).map(Outcome::Prepared)
        })?;
        self.preparations += 1;
        Ok(id)
    }

    fn consume(&mut self, id: usize) -> Result<B::Prepared> {
        let outcome = self.wait(id);
        self.preparations -= 1;
        match outcome? {
            Outcome::Prepared(prepared) => Ok(prepared),
            _ => panic!("preparation task returned a different task kind"),
        }
    }

    fn walk(&mut self, root: B::Entry, visited: &mut BTreeSet<PathBuf>) -> Result<()> {
        let mut frames: Vec<Frame<B>> = vec![Frame::Entry(root)];
        while let Some(frame) = frames.pop() {
            self.backend.check_cancelled()?;
            self.harvest();
            if !self.errors.is_empty() {
                break;
            }
            let (prepared, preparation) = match frame {
                Frame::Finish(record) => {
                    self.records.push(Some(record));
                    continue;
                }
                Frame::Entry(entry) => {
                    let id = self.prepare(entry, None)?;
                    (self.consume(id)?, id)
                }
                Frame::Children {
                    mut entries,
                    mut prepared,
                    parent,
                } => {
                    if prepared.is_empty() {
                        let Some(entry) = entries.pop_front() else {
                            continue;
                        };
                        prepared.push_back(self.prepare(entry, Some(parent))?);
                    }
                    // Reserve one slot globally for a descendant frontier, even
                    // when suspended ancestors retain all speculative results.
                    while self.preparations < CAPACITY - 1 {
                        let Some(entry) = entries.pop_front() else {
                            break;
                        };
                        prepared.push_back(self.prepare(entry, Some(parent))?);
                    }
                    let id = prepared.pop_front().expect("frontier preparation");
                    frames.push(Frame::Children {
                        entries,
                        prepared,
                        parent,
                    });
                    (self.consume(id)?, id)
                }
            };
            let ordinal = self.next_ordinal;
            self.next_ordinal = self
                .next_ordinal
                .checked_add(1)
                .expect("entry ordinal overflow");
            match self.backend.classify(prepared, visited)? {
                Node::Skip => {}
                Node::Record(record) => self.records.push(Some(record)),
                Node::Expand(request) => {
                    let id = self.submit(
                        TaskClass::Enumerate,
                        Some(preparation),
                        Some(ordinal),
                        move |backend, _| {
                            let (children, record) = backend.expand(request)?;
                            Ok(Outcome::Expanded(children, record))
                        },
                    )?;
                    let Outcome::Expanded(children, record) = self.wait(id)? else {
                        panic!("expansion task returned a different task kind")
                    };
                    frames.push(Frame::Finish(record));
                    frames.push(Frame::Children {
                        entries: children.into(),
                        prepared: VecDeque::new(),
                        parent: id,
                    });
                }
                Node::File(request, record) => {
                    while self.files.len() == CAPACITY {
                        self.receive()?;
                    }
                    if !self.errors.is_empty() {
                        break;
                    }
                    let id = self.submit(
                        TaskClass::File,
                        Some(preparation),
                        Some(ordinal),
                        move |backend, buffer| backend.read(request, buffer).map(Outcome::Read),
                    )?;
                    let index = self.records.len();
                    self.records.push(None);
                    assert!(self.files.insert(id, (ordinal, index, record)).is_none());
                }
            }
        }
        Ok(())
    }
}

impl<B: InventoryBackend> Drop for Traversal<'_, B> {
    fn drop(&mut self) {
        // Completion storage holds every outstanding result. No worker depends
        // on another worker or a controller callback to release its resources.
        while self.pending != 0 {
            let completion = self
                .receiver
                .recv()
                .expect("inventory result queue disconnected");
            self.apply(completion);
        }
    }
}
