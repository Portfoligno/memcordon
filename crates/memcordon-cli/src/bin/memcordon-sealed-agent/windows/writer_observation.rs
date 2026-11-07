//! Bounded historical producer observations. Never cleanup or retirement authority.
use super::writer_lifecycle::{
    self as model, Availability, Binding, DriverOutcome, DriverPhase, History, Owner, Stage,
    ThreadObservation, WriterSnapshot,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, LazyLock, Mutex, OnceLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::Instant,
};

const CAPACITY: usize = 16;
static DROPPED: AtomicU64 = AtomicU64::new(0);
static SEQUENCE: AtomicU64 = AtomicU64::new(1);
static JOURNAL: LazyLock<Mutex<Journal>> = LazyLock::new(|| Mutex::new(Journal::default()));

#[derive(Default)]
struct Journal {
    cells: VecDeque<Arc<Cell>>,
    evicted: u64,
    current_owner: Option<Owner>,
}

/// No sender, lane, queued record, publication lock or workload handle belongs here.
pub(super) struct Cell {
    pub generation: u64,
    attempt_id: String,
    source_binding: Binding,
    source_owner: OnceLock<Owner>,
    state: Mutex<State>,
}
struct State {
    history: History,
    thread: Option<JoinHandle<()>>,
}
impl Cell {
    pub(super) fn publisher_binding(&self) -> Binding {
        Binding {
            owner: self.source_owner.get().copied(),
            ..self.source_binding.clone()
        }
    }
}

fn dropped() {
    let _ = DROPPED.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        Some(value.saturating_add(1))
    });
}
fn sequence() -> Option<u64> {
    SEQUENCE
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .ok()
}

fn changed() {
    if sequence().is_none() {
        dropped();
    }
}

pub(super) fn begin(attempt_id: &str, request_sha256: &str) {
    let Some(generation) = sequence() else {
        dropped();
        return;
    };
    let Ok(mut journal) = JOURNAL.try_lock() else {
        dropped();
        return;
    };
    if journal.cells.len() == CAPACITY {
        journal.cells.pop_front();
        journal.evicted = journal.evicted.saturating_add(1);
    }
    let binding = Binding {
        attempt_id: attempt_id.into(),
        request_sha256: request_sha256.into(),
        owner: None,
        generation,
    };
    let history = History::new(binding.clone());
    journal.cells.push_back(Arc::new(Cell {
        generation,
        attempt_id: attempt_id.into(),
        source_binding: binding,
        source_owner: OnceLock::new(),
        state: Mutex::new(State {
            history,
            thread: None,
        }),
    }));
}

pub(super) fn get(attempt_id: &str) -> Option<Arc<Cell>> {
    let Ok(journal) = JOURNAL.try_lock() else {
        dropped();
        return None;
    };
    journal
        .cells
        .iter()
        .rev()
        .find(|cell| cell.attempt_id == attempt_id)
        .cloned()
}

pub(super) fn bind_owner(attempt_id: &str, owner: Owner) {
    if let Ok(mut journal) = JOURNAL.try_lock() {
        journal.current_owner = Some(owner);
        changed();
    } else {
        dropped();
    }
    let Some(cell) = get(attempt_id) else {
        return;
    };
    if let Ok(mut state) = cell.state.try_lock() {
        state.history.bind_owner(owner);
        let _ = cell.source_owner.set(owner);
        changed();
    } else {
        dropped();
    }
}

pub(super) fn stage(attempt_id: &str, stage: Stage, native_code: Option<u32>) {
    if let Some(cell) = get(attempt_id) {
        stage_cell(&cell, stage, native_code);
    }
}

pub(super) fn stage_cell(cell: &Cell, stage: Stage, native_code: Option<u32>) {
    if let Ok(mut state) = cell.state.try_lock() {
        state.history.transition(stage, native_code);
        changed();
    } else {
        dropped();
    }
}

pub(super) fn stage_weak(cell: &Option<Weak<Cell>>, stage: Stage, native_code: Option<u32>) {
    if let Some(cell) = cell.as_ref().and_then(Weak::upgrade) {
        stage_cell(&cell, stage, native_code);
    }
}

/// Only a weak diagnostic cell survives across the existing driver operation.
/// This cannot keep a writer, sender, lease or native thread alive.
pub(super) struct DriverObservation {
    cell: Option<Weak<Cell>>,
    phase: DriverPhase,
}

pub(super) fn driver(
    attempt_id: &str,
    request_sha256: &str,
    phase: DriverPhase,
) -> DriverObservation {
    let observation = DriverObservation {
        cell: get(attempt_id).and_then(|cell| {
            let matches = match cell.state.try_lock() {
                Ok(state) => state.history.snapshot().binding.request_sha256 == request_sha256,
                Err(_) => {
                    dropped();
                    false
                }
            };
            matches.then(|| Arc::downgrade(&cell))
        }),
        phase,
    };
    observation.record(DriverOutcome::Attempted);
    observation
}

impl DriverObservation {
    pub(super) fn transport(&self) -> TransportObservation {
        TransportObservation {
            cell: if self.phase == DriverPhase::TerminalDelivery {
                self.cell.clone()
            } else {
                None
            },
        }
    }
    fn record(&self, outcome: DriverOutcome) {
        if let Some(cell) = self.cell.as_ref().and_then(Weak::upgrade) {
            if let Ok(mut state) = cell.state.try_lock() {
                state.history.driver_transition(self.phase, outcome);
                changed();
            } else {
                dropped();
            }
        }
    }

    /// Preserve the operation and its exact error; observations cannot decide it.
    pub(super) fn run<T, E>(self, operation: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
        let result = operation();
        self.record(if result.is_ok() {
            DriverOutcome::Succeeded
        } else {
            DriverOutcome::Failed
        });
        result
    }
}
pub(super) struct TransportObservation {
    cell: Option<Weak<Cell>>,
}
impl TransportObservation {
    pub(super) fn record(&self, update: model::TransportUpdate) {
        let Some(cell) = self.cell.as_ref().and_then(Weak::upgrade) else {
            dropped();
            return;
        };
        if let Ok(mut state) = cell.state.try_lock() {
            if !state
                .history
                .transport_transition(&cell.publisher_binding(), update)
            {
                dropped();
            }
            changed();
        } else {
            dropped();
        }
    }
}

pub(super) fn retain_thread(cell: &Option<Arc<Cell>>, handle: JoinHandle<()>) {
    if let Some(cell) = cell {
        if let Ok(mut state) = cell.state.try_lock() {
            state.thread = Some(handle);
            changed();
            return;
        }
        dropped();
    }
    // Dropping this diagnostic handle preserves the preexisting detached-handle behavior.
    drop(handle);
}

pub(super) struct Local {
    pub attempt_id: String,
    pub generation: Option<u64>,
    pub pending: usize,
    pub quarantined: bool,
    pub publisher_native_code: Option<u32>,
    pub publisher_failure: Option<model::PublisherFailureSnapshot>,
}
pub(super) struct LocalRegistry {
    pub availability: Availability,
    pub total: Option<usize>,
    pub rows: Vec<Local>,
}

pub(super) fn snapshot(cutoff: Instant, local: impl FnOnce() -> LocalRegistry) -> model::Snapshot {
    let mut output = model::Snapshot {
        dropped: DROPPED.load(Ordering::Acquire),
        ..Default::default()
    };
    if Instant::now() >= cutoff {
        output.history = Availability::Cutoff;
        output.registry = Availability::Cutoff;
        return output;
    }
    let before = SEQUENCE.load(Ordering::Acquire);
    let cells = match JOURNAL.try_lock() {
        Ok(journal) => {
            output.history = Availability::Available;
            output.current_owner = journal.current_owner;
            output.evicted = journal.evicted;
            journal.cells.iter().cloned().collect::<Vec<_>>()
        }
        Err(std::sync::TryLockError::WouldBlock) => {
            output.history = Availability::Busy;
            Vec::new()
        }
        Err(std::sync::TryLockError::Poisoned(_)) => {
            output.history = Availability::Poisoned;
            Vec::new()
        }
    };
    if Instant::now() >= cutoff {
        output.registry = Availability::Cutoff;
        return output;
    }
    let local = local();
    output.registry = local.availability;
    output.total_lanes = local.total;
    if output.registry == Availability::Available {
        output.total_pending = Some(
            local
                .rows
                .iter()
                .fold(0usize, |total, row| total.saturating_add(row.pending)),
        );
        output.total_quarantined = Some(local.rows.iter().filter(|row| row.quarantined).count());
    }
    for cell in cells {
        if Instant::now() >= cutoff {
            output.history = Availability::Cutoff;
            break;
        }
        let state = match cell.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => {
                output.history = Availability::Busy;
                output.changed = true;
                continue;
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                output.history = Availability::Poisoned;
                output.changed = true;
                continue;
            }
        };
        let history = state.history.snapshot();
        let found = local.rows.iter().find(|row| {
            row.attempt_id == cell.attempt_id && row.generation == Some(cell.generation)
        });
        let present = if output.registry == Availability::Available {
            Some(found.is_some())
        } else {
            None
        };
        output.records.push(WriterSnapshot {
            history,
            registry_present: present,
            pending: found.map(|row| row.pending),
            quarantined: found.map(|row| row.quarantined),
            publisher_native_code: found.and_then(|row| row.publisher_native_code),
            publisher_failure: found.and_then(|row| row.publisher_failure.clone()),
            thread: match &state.thread {
                Some(handle) => thread_observation(handle, cutoff),
                None => ThreadObservation::NoHandle,
            },
            changed: false,
        });
    }
    output.changed |= before != SEQUENCE.load(Ordering::Acquire)
        || output.dropped != DROPPED.load(Ordering::Acquire);
    output.dropped = DROPPED.load(Ordering::Acquire);
    let sampled_at = Instant::now();
    output.sampled_at = Some(sampled_at);
    output.completed_before_cutoff = sampled_at < cutoff;
    output
}

fn thread_observation(handle: &JoinHandle<()>, cutoff: Instant) -> ThreadObservation {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::{FILETIME, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{GetThreadId, GetThreadTimes, WaitForSingleObject},
    };
    if Instant::now() >= cutoff {
        return ThreadObservation::Cutoff;
    }
    // SAFETY: borrow the retained original thread object; this zero-time wait cannot block.
    let status = unsafe { WaitForSingleObject(handle.as_raw_handle().cast(), 0) };
    if status == WAIT_FAILED {
        return ThreadObservation::Unavailable {
            native_code: std::io::Error::last_os_error()
                .raw_os_error()
                .map(|code| code as u32),
        };
    }
    if status != WAIT_OBJECT_0 && status != WAIT_TIMEOUT {
        return ThreadObservation::Unavailable { native_code: None };
    }
    if Instant::now() >= cutoff {
        return ThreadObservation::Cutoff;
    }
    // SAFETY: handle remains owned and live throughout each query.
    let tid = unsafe { GetThreadId(handle.as_raw_handle().cast()) };
    if tid == 0 {
        return ThreadObservation::Unavailable {
            native_code: std::io::Error::last_os_error()
                .raw_os_error()
                .map(|code| code as u32),
        };
    }
    if Instant::now() >= cutoff {
        return ThreadObservation::Cutoff;
    }
    let (mut creation, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: same borrowed thread handle and correctly sized outputs; exit time is not interpreted.
    if unsafe {
        GetThreadTimes(
            handle.as_raw_handle().cast(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return ThreadObservation::Unavailable {
            native_code: std::io::Error::last_os_error()
                .raw_os_error()
                .map(|code| code as u32),
        };
    }
    let birth = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if birth == 0 {
        return ThreadObservation::Unavailable { native_code: None };
    }
    if status == WAIT_OBJECT_0 {
        ThreadObservation::Exited { tid, birth }
    } else {
        ThreadObservation::Running { tid, birth }
    }
}
