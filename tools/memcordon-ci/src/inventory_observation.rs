//! Bounded, std-only observation state. Diagnostic counters never enter identities.
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_ACTORS: usize = 32;
pub const MAX_TASKS: usize = 64;
pub const OPERATION_COUNT: usize = 25;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);
impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn check(&self) -> io::Result<()> {
        if self.0.load(Ordering::Acquire) {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "inventory cancelled",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskClass {
    Prepare,
    Enumerate,
    File,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    Offered,
    Started,
    Ready,
    Received,
}

#[derive(Clone, Debug, Default)]
pub struct TaskCounters {
    pub offered: u64,
    pub started: u64,
    pub ready: u64,
    pub received: u64,
    pub files_attempted: u64,
    pub files_completed: u64,
    pub files_validated: u64,
    pub files_committed: u64,
    pub validated_bytes: u64,
    pub committed_bytes: u64,
    pub queue_ns: u64,
    pub result_residence_ns: u64,
}
struct Task {
    class: TaskClass,
    state: TaskState,
    changed: Instant,
    parent: Option<u64>,
    ordinal: Option<u64>,
}
#[derive(Clone, Debug)]
pub struct TaskEvent {
    pub id: u64,
    pub parent: Option<u64>,
    pub ordinal: Option<u64>,
    pub state: TaskState,
    pub at_ns: u64,
}
#[derive(Default)]
struct Ledger {
    tasks: BTreeMap<u64, Task>,
    totals: TaskCounters,
    events: VecDeque<TaskEvent>,
    overwritten: u64,
}
impl Ledger {
    fn event(&mut self, event: TaskEvent) {
        if self.events.len() == 256 {
            self.events.pop_front();
            self.overwritten += 1;
        }
        self.events.push_back(event);
    }
}

#[derive(Clone, Debug)]
pub struct Counters {
    pub counts: [u64; OPERATION_COUNT],
    pub inclusive_ns: [u64; OPERATION_COUNT],
    pub exclusive_ns: [u64; OPERATION_COUNT],
    pub panics: u64,
    pub bytes: u64,
    pub read_calls: u64,
    pub read_ns: u64,
    pub hash_ns: u64,
    pub published_ns: u64,
    pub idle_ns: u64,
    pub task_other_ns: u64,
}
impl Default for Counters {
    fn default() -> Self {
        Self {
            counts: [0; OPERATION_COUNT],
            inclusive_ns: [0; OPERATION_COUNT],
            exclusive_ns: [0; OPERATION_COUNT],
            panics: 0,
            bytes: 0,
            read_calls: 0,
            read_ns: 0,
            hash_ns: 0,
            published_ns: 0,
            idle_ns: 0,
            task_other_ns: 0,
        }
    }
}
#[derive(Default)]
struct Active {
    generation: AtomicU64,
    operation: AtomicU64,
    started_ns: AtomicU64,
    task: AtomicU64,
}
impl Active {
    fn set(&self, operation: Option<usize>, started_ns: u64, task: Option<u64>) {
        let sequence = self.generation.load(Ordering::SeqCst);
        assert!(sequence < u64::MAX - 2, "inventory generation exhausted");
        self.generation.store(sequence + 1, Ordering::SeqCst);
        self.operation
            .store(operation.map_or(0, |op| op as u64 + 1), Ordering::SeqCst);
        self.started_ns.store(started_ns, Ordering::SeqCst);
        self.task.store(
            task.map_or(0, |id| id.checked_add(1).expect("task id exhausted")),
            Ordering::SeqCst,
        );
        self.generation.store(sequence + 2, Ordering::SeqCst);
    }
    fn sample(&self) -> Option<(u64, Option<usize>, u64, Option<u64>)> {
        for _ in 0..2 {
            let before = self.generation.load(Ordering::SeqCst);
            if !before.is_multiple_of(2) {
                continue;
            }
            let operation = self.operation.load(Ordering::SeqCst);
            let started = self.started_ns.load(Ordering::SeqCst);
            let task = self.task.load(Ordering::SeqCst).checked_sub(1);
            if self.generation.load(Ordering::SeqCst) == before {
                return Some((
                    before,
                    operation.checked_sub(1).map(|op| op as usize),
                    started,
                    task,
                ));
            }
        }
        None
    }
}
struct Slot {
    active: Active,
    counters: Mutex<Counters>,
    path: Mutex<String>,
}
struct Local {
    slot: Arc<Slot>,
    counters: RefCell<Counters>,
    leaf: RefCell<Option<(usize, Instant)>>,
    depth: RefCell<usize>,
    epoch: Instant,
    boundary: Cell<Instant>,
    task: Cell<Option<u64>>,
}
impl Local {
    fn publish(&self) {
        let mut counters = self.counters.borrow_mut();
        counters.published_ns = nanos(self.epoch.elapsed());
        *self.slot.counters.lock().expect("actor counters poisoned") = counters.clone();
    }
    fn checkpoint(&self) {
        if nanos(self.epoch.elapsed()).saturating_sub(self.counters.borrow().published_ns)
            >= 1_000_000_000
        {
            self.publish();
        }
    }
    fn change_leaf(&self, next: Option<usize>) {
        let now = Instant::now();
        let boundary = self.boundary.replace(now);
        if let Some((operation, started)) = self.leaf.replace(next.map(|op| (op, now))) {
            self.counters.borrow_mut().exclusive_ns[operation] +=
                nanos(now.duration_since(started));
        } else if self.task.get().is_some() {
            self.counters.borrow_mut().task_other_ns += nanos(now.duration_since(boundary));
        } else {
            self.counters.borrow_mut().idle_ns += nanos(now.duration_since(boundary));
        }
        self.slot
            .active
            .set(next, nanos(now.duration_since(self.epoch)), self.task.get());
    }
    fn task(&self, task: Option<u64>) {
        self.change_leaf(None);
        self.task.set(task);
        self.slot
            .active
            .set(None, nanos(self.epoch.elapsed()), task);
        self.publish();
    }
}
thread_local! { static LOCALS: RefCell<Vec<(u64, Rc<Local>)>> = const { RefCell::new(Vec::new()) }; }

struct Shared {
    id: u64,
    epoch: Instant,
    slots: Mutex<Vec<Arc<Slot>>>,
    ledger: Mutex<Ledger>,
    cancel: CancellationToken,
}
#[derive(Clone)]
pub struct Observer(Arc<Shared>);
#[derive(Clone, Debug)]
pub struct ActorSnapshot {
    pub task: Option<u64>,
    pub generation: Option<u64>,
    pub operation: Option<usize>,
    pub started_ns: u64,
    pub counters: Option<Counters>,
    pub path: String,
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub root_id: u64,
    pub elapsed_ns: u64,
    pub actors: Vec<ActorSnapshot>,
    pub tasks: TaskCounters,
    pub outstanding: usize,
    pub events: Vec<TaskEvent>,
    pub overwritten_events: u64,
}
pub struct Span {
    local: Rc<Local>,
    operation: usize,
    started: Instant,
    previous: Option<usize>,
}
impl Drop for Span {
    fn drop(&mut self) {
        self.local.change_leaf(self.previous);
        {
            let mut counters = self.local.counters.borrow_mut();
            counters.counts[self.operation] += 1;
            counters.inclusive_ns[self.operation] += nanos(self.started.elapsed());
            if std::thread::panicking() {
                counters.panics += 1;
            }
        }
        let outermost = {
            let mut depth = self.local.depth.borrow_mut();
            *depth -= 1;
            *depth == 0
        };
        if outermost {
            self.local.publish();
        } else {
            self.local.checkpoint();
        }
    }
}
fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().try_into().unwrap_or(u64::MAX)
}

impl Default for Observer {
    fn default() -> Self {
        Self::new()
    }
}
impl Observer {
    pub fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        assert_ne!(id, u64::MAX, "inventory observer identifiers exhausted");
        Self(Arc::new(Shared {
            id,
            epoch: Instant::now(),
            slots: Mutex::new(Vec::new()),
            ledger: Mutex::new(Ledger::default()),
            cancel: CancellationToken::default(),
        }))
    }
    fn local(&self) -> Rc<Local> {
        LOCALS.with(|locals| {
            let mut locals = locals.borrow_mut();
            if let Some((_, local)) = locals.iter().find(|(id, _)| *id == self.0.id) {
                return Rc::clone(local);
            }
            // A thread retains only four recent observers, never one per root.
            if locals.len() == 4 {
                locals.remove(0);
            }
            let mut slots = self.0.slots.lock().expect("actor registry poisoned");
            assert!(slots.len() < MAX_ACTORS, "inventory actor bound exceeded");
            let slot = Arc::new(Slot {
                active: Active::default(),
                counters: Mutex::new(Counters::default()),
                path: Mutex::new(String::new()),
            });
            slots.push(Arc::clone(&slot));
            let local = Rc::new(Local {
                slot,
                counters: RefCell::new(Counters::default()),
                leaf: RefCell::new(None),
                depth: RefCell::new(0),
                epoch: self.0.epoch,
                boundary: Cell::new(Instant::now()),
                task: Cell::new(None),
            });
            locals.push((self.0.id, Rc::clone(&local)));
            local
        })
    }
    pub fn span(&self, operation: usize, path: &std::path::Path) -> Span {
        assert!(operation < OPERATION_COUNT);
        let local = self.local();
        let previous = local.leaf.borrow().map(|(op, _)| op);
        if previous.is_none() {
            // Bounded diagnostic sample only; manifest paths remain lossless.
            let sample: String = path
                .as_os_str()
                .to_string_lossy()
                .chars()
                .take(256)
                .collect();
            *local.slot.path.lock().expect("actor path poisoned") = sample;
        }
        *local.depth.borrow_mut() += 1;
        local.change_leaf(Some(operation));
        Span {
            local,
            operation,
            started: Instant::now(),
            previous,
        }
    }
    pub fn record_chunk(&self, read: Duration, hash: Duration, bytes: u64) {
        let local = self.local();
        {
            let mut counters = local.counters.borrow_mut();
            counters.read_calls += 1;
            counters.bytes += bytes;
            counters.read_ns += nanos(read);
            counters.hash_ns += nanos(hash);
        }
        local.checkpoint();
    }
    pub fn cancellation(&self) -> CancellationToken {
        self.0.cancel.clone()
    }
    pub fn task_transition(&self, id: u64, class: TaskClass, state: TaskState) -> io::Result<()> {
        let mut ledger = self.0.ledger.lock().expect("inventory ledger poisoned");
        let now = Instant::now();
        match state {
            TaskState::Offered => {
                if ledger.tasks.len() == MAX_TASKS || ledger.tasks.contains_key(&id) {
                    return Err(io::Error::other("inventory task admission invariant"));
                }
                ledger.tasks.insert(
                    id,
                    Task {
                        class,
                        state,
                        changed: now,
                        parent: None,
                        ordinal: None,
                    },
                );
                ledger.totals.offered += 1;
                if class == TaskClass::File {
                    ledger.totals.files_attempted += 1;
                }
            }
            _ => {
                let expected = match state {
                    TaskState::Started => TaskState::Offered,
                    TaskState::Ready => TaskState::Started,
                    TaskState::Received => TaskState::Ready,
                    TaskState::Offered => unreachable!(),
                };
                let task = ledger
                    .tasks
                    .get_mut(&id)
                    .ok_or_else(|| io::Error::other("unknown inventory task"))?;
                if task.class != class || task.state != expected {
                    return Err(io::Error::other("inventory task transition invariant"));
                }
                let elapsed = nanos(now.duration_since(task.changed));
                task.changed = now;
                task.state = state;
                match state {
                    TaskState::Started => {
                        ledger.totals.started += 1;
                        ledger.totals.queue_ns += elapsed;
                    }
                    TaskState::Ready => {
                        ledger.totals.ready += 1;
                        if class == TaskClass::File {
                            ledger.totals.files_completed += 1;
                        }
                    }
                    TaskState::Received => {
                        ledger.totals.received += 1;
                        ledger.totals.result_residence_ns += elapsed;
                        ledger.tasks.remove(&id);
                    }
                    TaskState::Offered => unreachable!(),
                }
            }
        }
        let (parent, ordinal) = ledger
            .tasks
            .get(&id)
            .map_or((None, None), |task| (task.parent, task.ordinal));
        ledger.event(TaskEvent {
            id,
            parent,
            ordinal,
            state,
            at_ns: nanos(self.0.epoch.elapsed()),
        });
        drop(ledger);
        match state {
            TaskState::Started => self.local().task(Some(id)),
            TaskState::Ready => self.local().task(None),
            _ => (),
        }
        Ok(())
    }
    pub fn task_dependency(
        &self,
        id: u64,
        parent: Option<u64>,
        ordinal: Option<u64>,
    ) -> io::Result<()> {
        let mut ledger = self.0.ledger.lock().expect("inventory ledger poisoned");
        let task = ledger
            .tasks
            .get_mut(&id)
            .ok_or_else(|| io::Error::other("unknown task dependency"))?;
        task.parent = parent;
        task.ordinal = ordinal;
        let state = task.state;
        ledger.event(TaskEvent {
            id,
            parent,
            ordinal,
            state,
            at_ns: nanos(self.0.epoch.elapsed()),
        });
        Ok(())
    }
    pub fn file_validated(&self, bytes: u64) {
        let mut ledger = self.0.ledger.lock().expect("inventory ledger poisoned");
        ledger.totals.files_validated += 1;
        ledger.totals.validated_bytes += bytes;
    }
    pub fn file_committed(&self, bytes: u64) {
        let mut ledger = self.0.ledger.lock().expect("inventory ledger poisoned");
        ledger.totals.files_committed += 1;
        ledger.totals.committed_bytes += bytes;
        assert!(
            ledger.totals.files_committed <= ledger.totals.files_validated
                && ledger.totals.committed_bytes <= ledger.totals.validated_bytes,
            "unvalidated inventory commit"
        );
    }
    pub fn snapshot(&self) -> Snapshot {
        LOCALS.with(|locals| {
            if let Some((_, local)) = locals.borrow().iter().find(|(id, _)| *id == self.0.id) {
                local.publish();
            }
        });
        let slots = self
            .0
            .slots
            .lock()
            .expect("actor registry poisoned")
            .clone();
        let actors = slots
            .iter()
            .map(|slot| {
                let active = slot.active.sample();
                ActorSnapshot {
                    task: active.and_then(|v| v.3),
                    generation: active.map(|v| v.0),
                    operation: active.and_then(|v| v.1),
                    started_ns: active.map_or(0, |v| v.2),
                    counters: slot.counters.try_lock().ok().map(|v| v.clone()),
                    path: slot
                        .path
                        .try_lock()
                        .ok()
                        .map_or_else(String::new, |v| v.clone()),
                }
            })
            .collect();
        let ledger = self.0.ledger.lock().expect("inventory ledger poisoned");
        Snapshot {
            root_id: self.0.id,
            elapsed_ns: nanos(self.0.epoch.elapsed()),
            actors,
            tasks: ledger.totals.clone(),
            outstanding: ledger.tasks.len(),
            events: ledger.events.iter().cloned().collect(),
            overwritten_events: ledger.overwritten,
        }
    }
}
