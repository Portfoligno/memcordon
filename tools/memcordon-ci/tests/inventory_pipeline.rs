use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

use memcordon_ci::inventory_pipeline::{InventoryBackend, InventorySession, Node, ValidatedDigest};
use memcordon_ci::inventory_progress::{TaskClass, TaskState};
use memcordon_ci::inventory_workers::CAPACITY;
use memcordon_ci::{CiError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Prepare,
    Expand,
    Read,
    Classify,
}

enum Kind {
    Directory(Vec<usize>),
    File,
    Alias(usize),
}
type Hook = dyn Fn(Event, usize) -> Result<()> + Send + Sync;

struct Backend {
    tree: BTreeMap<usize, Kind>,
    hook: Arc<Hook>,
    cancelled: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl Backend {
    fn new(
        tree: BTreeMap<usize, Kind>,
        hook: impl Fn(Event, usize) -> Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            tree,
            hook: Arc::new(hook),
            cancelled: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl InventoryBackend for Backend {
    type Entry = usize;
    type Prepared = usize;
    type Expansion = usize;
    type File = usize;
    type Record = (usize, Option<String>);

    fn is_leaf_hint(&self, entry: &usize) -> bool {
        matches!(self.tree[entry], Kind::File)
    }

    fn prepare(&self, id: usize) -> Result<usize> {
        (self.hook)(Event::Prepare, id)?;
        Ok(id)
    }
    fn classify(
        &self,
        id: usize,
        visited: &mut BTreeSet<PathBuf>,
    ) -> Result<Node<usize, usize, Self::Record>> {
        (self.hook)(Event::Classify, id)?;
        let identity = match self.tree[&id] {
            Kind::Alias(target) => target,
            _ => id,
        };
        if !visited.insert(PathBuf::from(identity.to_string())) {
            return Ok(Node::Skip);
        }
        match &self.tree[&identity] {
            Kind::Directory(_) => Ok(Node::Expand(identity)),
            Kind::File => Ok(Node::File(identity, (identity, None))),
            Kind::Alias(_) => panic!("fixture aliases must resolve to ordinary entries"),
        }
    }
    fn expand(&self, id: usize) -> Result<(Vec<usize>, Self::Record)> {
        (self.hook)(Event::Expand, id)?;
        let Kind::Directory(children) = &self.tree[&id] else {
            panic!("not a directory")
        };
        Ok((children.clone(), (id, None)))
    }
    fn read(&self, id: usize, buffer: &mut [u8]) -> Result<ValidatedDigest> {
        assert_eq!(buffer.len(), memcordon_ci::inventory_reader::BUFFER_SIZE);
        (self.hook)(Event::Read, id)?;
        Ok(ValidatedDigest {
            digest: id.to_string(),
            bytes: 1,
        })
    }
    fn set_digest(&self, record: &mut Self::Record, digest: ValidatedDigest) {
        record.1 = Some(digest.digest);
    }
    fn check_cancelled(&self) -> Result<()> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(CiError::Message("injected cancellation".into()))
        } else {
            Ok(())
        }
    }
    fn transition(&self, _: u64, _: TaskClass, state: TaskState) -> Result<()> {
        match state {
            TaskState::Offered => {
                let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(active, Ordering::SeqCst);
            }
            TaskState::Received => {
                self.active.fetch_sub(1, Ordering::SeqCst);
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Gate(Arc<(Mutex<bool>, Condvar)>);
impl Gate {
    fn wait(&self) {
        let (lock, wake) = &*self.0;
        drop(
            wake.wait_while(lock.lock().unwrap(), |open| !*open)
                .unwrap(),
        );
    }
    fn release(&self) {
        let (lock, wake) = &*self.0;
        *lock.lock().unwrap() = true;
        wake.notify_all();
    }
}

#[test]
fn earlier_file_and_directory_start_before_late_preparation_completes() {
    let gate = Gate::default();
    let (started, observed) = mpsc::channel();
    let backend = Backend::new(
        BTreeMap::from([
            (0, Kind::Directory(vec![1, 2, 9])),
            (1, Kind::File),
            (2, Kind::Directory(vec![3])),
            (3, Kind::File),
            (9, Kind::File),
        ]),
        {
            let gate = gate.clone();
            move |event, id| {
                if event == Event::Prepare && id == 9 {
                    gate.wait();
                }
                if (event == Event::Read && id == 1) || (event == Event::Expand && id == 2) {
                    started.send(event).unwrap();
                }
                Ok(())
            }
        },
    );
    let controller = std::thread::spawn(move || {
        InventorySession::new()
            .unwrap()
            .measure(backend, 0, &mut BTreeSet::new())
    });
    let first = observed.recv_timeout(Duration::from_secs(5));
    let second = observed.recv_timeout(Duration::from_secs(5));
    gate.release();
    let records = controller.join().unwrap().unwrap();
    assert!(
        first.is_ok() && second.is_ok(),
        "a late sibling preparation held the whole directory: {first:?}, {second:?}"
    );
    assert_eq!(records.len(), 5);
}

#[test]
fn suspended_ancestor_results_leave_a_frontier_slot_at_every_depth() {
    let mut tree = BTreeMap::new();
    let depth = CAPACITY * 4;
    tree.insert(0, Kind::Directory((1..=CAPACITY).collect()));
    for id in 2..=CAPACITY {
        tree.insert(id, Kind::File);
    }
    tree.insert(1, Kind::Directory(vec![CAPACITY + 1]));
    for id in CAPACITY + 1..CAPACITY + depth {
        tree.insert(id, Kind::Directory(vec![id + 1]));
    }
    tree.insert(CAPACITY + depth, Kind::File);
    let gate = Gate::default();
    let (started, observed) = mpsc::channel();
    let backend = Backend::new(tree, {
        let gate = gate.clone();
        move |event, id| {
            if event == Event::Prepare && (2..CAPACITY).contains(&id) {
                gate.wait();
            }
            if event == Event::Read && id == CAPACITY + depth {
                started.send(()).unwrap();
            }
            Ok(())
        }
    });
    let peak = Arc::clone(&backend.peak);
    let active = Arc::clone(&backend.active);
    let controller = std::thread::spawn(move || {
        InventorySession::new()
            .unwrap()
            .measure(backend, 0, &mut BTreeSet::new())
    });
    let progressed = observed.recv_timeout(Duration::from_secs(5));
    gate.release();
    let records = controller.join().unwrap().unwrap();
    assert!(
        progressed.is_ok(),
        "ancestor speculation starved descendant frontier: {progressed:?}"
    );
    assert_eq!(records.len(), CAPACITY + depth + 1);
    assert!(peak.load(Ordering::SeqCst) <= memcordon_ci::inventory_pipeline::ADMISSION);
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[test]
fn earlier_file_error_wins_over_later_directory_error_after_root_fence() {
    let gate = Gate::default();
    let backend = Backend::new(
        BTreeMap::from([
            (0, Kind::Directory(vec![1, 2])),
            (1, Kind::File),
            (2, Kind::Directory(vec![])),
        ]),
        {
            let gate = gate.clone();
            move |event, id| {
                if event == Event::Read && id == 1 {
                    gate.wait();
                    return Err(CiError::Message("earlier file".into()));
                }
                if event == Event::Expand && id == 2 {
                    gate.release();
                    return Err(CiError::Message("later directory".into()));
                }
                Ok(())
            }
        },
    );
    let error = InventorySession::new()
        .unwrap()
        .measure(backend, 0, &mut BTreeSet::new())
        .unwrap_err();
    assert_eq!(error.to_string(), "earlier file");
}

#[test]
fn nested_alias_claims_later_sibling_and_ancestor_cycles_terminate() {
    let visits = Arc::new(Mutex::new(Vec::new()));
    let backend = Backend::new(
        BTreeMap::from([
            (0, Kind::Directory(vec![1, 2])),
            (1, Kind::Directory(vec![3, 4])),
            (2, Kind::File),
            (3, Kind::Alias(2)),
            (4, Kind::Alias(0)),
        ]),
        {
            let visits = Arc::clone(&visits);
            move |event, id| {
                if event == Event::Classify {
                    visits.lock().unwrap().push(id);
                }
                Ok(())
            }
        },
    );
    let records = InventorySession::new()
        .unwrap()
        .measure(backend, 0, &mut BTreeSet::new())
        .unwrap();
    assert_eq!(*visits.lock().unwrap(), [0, 1, 3, 4, 2]);
    assert_eq!(records, [(2, Some("2".into())), (1, None), (0, None)]);
}

#[test]
fn failed_directory_enumeration_commits_no_children_and_session_is_reusable() {
    let session = InventorySession::new().unwrap();
    let backend = Backend::new(
        BTreeMap::from([(0, Kind::Directory(vec![1])), (1, Kind::File)]),
        |event, id| {
            assert!(
                !(event == Event::Prepare && id == 1),
                "failed listing exposed partial children"
            );
            if event == Event::Expand {
                return Err(CiError::Message("late iterator error".into()));
            }
            Ok(())
        },
    );
    assert!(session.measure(backend, 0, &mut BTreeSet::new()).is_err());
    let next = Backend::new(BTreeMap::from([(0, Kind::File)]), |_, _| Ok(()));
    assert_eq!(
        session.measure(next, 0, &mut BTreeSet::new()).unwrap(),
        [(0, Some("0".into()))]
    );
}

#[test]
fn worker_panic_and_cancellation_never_return_partial_success() {
    let session = InventorySession::new().unwrap();
    let backend = Backend::new(BTreeMap::from([(0, Kind::File)]), |event, _| {
        assert_ne!(event, Event::Read, "injected panic");
        Ok(())
    });
    assert!(
        session
            .measure(backend, 0, &mut BTreeSet::new())
            .unwrap_err()
            .to_string()
            .contains("worker panicked")
    );
    let backend = Backend::new(BTreeMap::from([(0, Kind::File)]), |_, _| Ok(()));
    backend.cancelled.store(true, Ordering::SeqCst);
    assert_eq!(
        session
            .measure(backend, 0, &mut BTreeSet::new())
            .unwrap_err()
            .to_string(),
        "injected cancellation"
    );
}

#[test]
fn file_admission_bounds_running_tasks_and_fences_the_tail() {
    let count = CAPACITY * 3;
    let mut tree = BTreeMap::from([(0, Kind::Directory((1..=count).collect()))]);
    tree.extend((1..=count).map(|id| (id, Kind::File)));
    let gate = Gate::default();
    let live = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (started, observed) = mpsc::channel();
    let backend = Backend::new(tree, {
        let gate = gate.clone();
        let live = Arc::clone(&live);
        let peak = Arc::clone(&peak);
        move |event, _| {
            if event == Event::Read {
                let current = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                started.send(()).unwrap();
                gate.wait();
                live.fetch_sub(1, Ordering::SeqCst);
            }
            Ok(())
        }
    });
    let controller = std::thread::spawn(move || {
        InventorySession::new()
            .unwrap()
            .measure(backend, 0, &mut BTreeSet::new())
    });
    let all_started = (0..CAPACITY).all(|_| observed.recv_timeout(Duration::from_secs(5)).is_ok());
    let at_gate = live.load(Ordering::SeqCst);
    gate.release();
    let records = controller.join().unwrap().unwrap();
    assert!(
        all_started,
        "shared executor did not service the existing file budget"
    );
    assert_eq!(at_gate, CAPACITY);
    assert!(peak.load(Ordering::SeqCst) <= CAPACITY);
    assert_eq!(live.load(Ordering::SeqCst), 0);
    assert_eq!(records.len(), count + 1);
    assert!(
        records
            .iter()
            .filter(|(id, _)| *id != 0)
            .all(|(_, digest)| digest.is_some())
    );
}

#[test]
fn received_sibling_results_keep_their_preparation_window_credits() {
    let count = CAPACITY * 4;
    let mut tree = BTreeMap::from([(0, Kind::Directory((1..=count).collect()))]);
    tree.extend((1..=count).map(|id| (id, Kind::File)));
    let gate = Gate::default();
    let prepared = Arc::new(AtomicUsize::new(0));
    let (started, observed) = mpsc::channel();
    let backend = Backend::new(tree, {
        let gate = gate.clone();
        let prepared = Arc::clone(&prepared);
        move |event, id| {
            if event == Event::Prepare {
                let total = prepared.fetch_add(1, Ordering::SeqCst) + 1;
                if total == CAPACITY {
                    started.send(()).unwrap();
                }
                if id == 1 {
                    gate.wait();
                }
            }
            Ok(())
        }
    });
    let controller = std::thread::spawn(move || {
        InventorySession::new()
            .unwrap()
            .measure(backend, 0, &mut BTreeSet::new())
    });
    let filled = observed.recv_timeout(Duration::from_secs(5));
    let count_before_release = prepared.load(Ordering::SeqCst);
    gate.release();
    let records = controller.join().unwrap().unwrap();
    assert!(filled.is_ok(), "lookahead did not fill its bounded window");
    // Includes the already-consumed root plus the child window minus its
    // reserved frontier slot. Ready siblings must not admit the rest of the tree.
    assert_eq!(count_before_release, CAPACITY);
    assert_eq!(records.len(), count + 1);
}
