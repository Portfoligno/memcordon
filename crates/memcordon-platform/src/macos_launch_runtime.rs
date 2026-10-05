//! Bounded, context-owned native creation and retirement storage.
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

const STATE_BITS: u32 = u8::BITS;
const STATE_MASK: u64 = u8::MAX as u64;
const MAX_GENERATION: u64 = u64::MAX >> STATE_BITS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum State {
    Vacant,
    Reserved,
    Spawning,
    Owned,
    Abandoned,
    Reaping,
    Complete,
    OwnershipLost,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SlotObservation {
    index: usize,
    ownership_before: u64,
    ownership_after: u64,
    state_before: String,
    state_after: String,
    pid: i32,
    cleanup_errno: i32,
    cancellation: bool,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct StartupCleanupObservation {
    pub(crate) observed_at: Option<u64>,
    pub(crate) settlement_finished: bool,
    pub(crate) normal_inspector_created: bool,
    outstanding: usize,
    slots: Vec<SlotObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SlotKey {
    index: usize,
    generation: u64,
}

fn packed(key: SlotKey, state: State) -> u64 {
    (key.generation << STATE_BITS) | state as u64
}
fn state(value: u64) -> u64 {
    value & STATE_MASK
}

#[cfg(feature = "test-support")]
fn state_name(value: u64) -> &'static str {
    [
        "Vacant",
        "Reserved",
        "Spawning",
        "Owned",
        "Abandoned",
        "Reaping",
        "Complete",
        "OwnershipLost",
    ]
    .get(state(value) as usize)
    .copied()
    .unwrap_or("Invalid")
}

pub(crate) enum CancellationScope {
    ProcessGroup,
    ChildlessInspector,
}

struct Slot {
    state: AtomicU64,
    pid: AtomicI32,
    cancellation: AtomicBool,
    cleanup_errno: AtomicI32,
    childless_inspector: AtomicBool,
}

type Operation = Box<dyn FnOnce() + Send>;
enum SpawnMessage {
    Work(Operation),
    Close,
}

struct Inner {
    slots: Box<[Slot]>,
    closing: AtomicBool,
    clients: AtomicUsize,
    spawn: mpsc::SyncSender<SpawnMessage>,
    wake: mpsc::SyncSender<()>,
}

/// Only public handles count as clients. Tickets and workers retain storage but
/// cannot prevent the last context from closing admission.
pub struct LaunchRuntime {
    inner: Arc<Inner>,
}
#[cfg(feature = "test-support")]
pub struct LaunchRuntimeObserver {
    inner: Arc<Inner>,
}
#[cfg(feature = "test-support")]
impl LaunchRuntimeObserver {
    pub fn outstanding(&self) -> usize {
        self.inner
            .slots
            .iter()
            .filter(|slot| state(slot.state.load(Ordering::Acquire)) != State::Vacant as u64)
            .count()
    }
}

impl Clone for LaunchRuntime {
    fn clone(&self) -> Self {
        self.inner
            .clients
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .expect("launch context client count overflow");
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Drop for LaunchRuntime {
    fn drop(&mut self) {
        if self.inner.clients.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.closing.store(true, Ordering::Release);
            let _ = self.inner.spawn.try_send(SpawnMessage::Close);
            let _ = self.inner.wake.try_send(());
        }
    }
}

impl LaunchRuntime {
    #[cfg(feature = "test-support")]
    pub(crate) fn startup_cleanup_observation(
        &self,
        settlement_finished: bool,
        normal_inspector_created: bool,
    ) -> StartupCleanupObservation {
        // These are concurrent observations, not ownership or cleanup receipts.
        // Retain both state/generation reads rather than pretending the fields
        // constitute an atomic snapshot of the native workers.
        let slots = self
            .inner
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                let ownership_before = slot.state.load(Ordering::Acquire);
                let pid = slot.pid.load(Ordering::Acquire);
                let cleanup_errno = slot.cleanup_errno.load(Ordering::Acquire);
                let cancellation = slot.cancellation.load(Ordering::Acquire);
                let ownership_after = slot.state.load(Ordering::Acquire);
                (state(ownership_before) != State::Vacant as u64
                    || state(ownership_after) != State::Vacant as u64)
                    .then_some(SlotObservation {
                        index,
                        ownership_before,
                        ownership_after,
                        state_before: state_name(ownership_before).into(),
                        state_after: state_name(ownership_after).into(),
                        pid,
                        cleanup_errno,
                        cancellation,
                    })
            })
            // Startup owns at most two inspector operations. Cap supplemental
            // telemetry independently so it always fits the existing frame.
            .take(8)
            .collect();
        StartupCleanupObservation {
            observed_at: crate::macos_deadline::continuous_nanos().ok(),
            settlement_finished,
            normal_inspector_created,
            outstanding: self.outstanding(),
            slots,
        }
    }

    pub fn new(capacity: usize) -> io::Result<Self> {
        if capacity == 0 || capacity > 256 {
            return Err(io::Error::other(
                "native runtime capacity must be within 1..=256",
            ));
        }
        let (spawn, receive) = mpsc::sync_channel(capacity);
        let (wake, events) = mpsc::sync_channel(1);
        let inner = Arc::new(Inner {
            slots: (0..capacity)
                .map(|_| Slot {
                    state: AtomicU64::new(0),
                    pid: AtomicI32::new(0),
                    cancellation: AtomicBool::new(false),
                    cleanup_errno: AtomicI32::new(0),
                    childless_inspector: AtomicBool::new(false),
                })
                .collect(),
            closing: AtomicBool::new(false),
            clients: AtomicUsize::new(1),
            spawn,
            wake,
        });
        let reaper = inner.clone();
        std::thread::Builder::new()
            .name("memcordon-native-retirement".into())
            .spawn(move || reap(reaper, events))?;
        let owner = inner.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("memcordon-native-creation".into())
            .spawn(move || {
                while let Ok(message) = receive.recv() {
                    match message {
                        SpawnMessage::Work(operation) => {
                            // Every accepted closure owns its already reserved ticket.
                            // Unwinding drops that ticket or its published local child.
                            let _ =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
                        }
                        SpawnMessage::Close => {}
                    }
                    if owner.closing.load(Ordering::Acquire) {
                        while let Ok(message) = receive.try_recv() {
                            if let SpawnMessage::Work(operation) = message {
                                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                                    operation,
                                ));
                            }
                        }
                        break;
                    }
                }
            })
        {
            inner.closing.store(true, Ordering::Release);
            let _ = inner.wake.try_send(());
            return Err(error);
        }
        Ok(Self { inner })
    }

    /// After creation admission has ended and all child owners have been dropped,
    /// verify that the retained native reaper discharged every reserved operation.
    pub(crate) fn settled_until(&self, deadline: std::time::Instant) -> bool {
        loop {
            if self
                .inner
                .slots
                .iter()
                .all(|slot| state(slot.state.load(Ordering::Acquire)) == State::Vacant as u64)
            {
                return true;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            std::thread::sleep(remaining.min(Duration::from_millis(2)));
        }
    }

    pub(crate) fn reserve(&self) -> io::Result<Ticket> {
        self.reserve_with_scope(CancellationScope::ProcessGroup)
    }

    pub(crate) fn reserve_with_scope(&self, scope: CancellationScope) -> io::Result<Ticket> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(io::Error::other("native runtime is closing"));
        }
        for (index, slot) in self.inner.slots.iter().enumerate() {
            let previous = slot.state.load(Ordering::Acquire);
            if state(previous) != State::Vacant as u64 {
                continue;
            }
            let generation = previous >> STATE_BITS;
            if generation == MAX_GENERATION {
                continue;
            }
            let key = SlotKey {
                index,
                generation: generation + 1,
            };
            if slot
                .state
                .compare_exchange(
                    previous,
                    packed(key, State::Reserved),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                slot.pid.store(0, Ordering::Relaxed);
                slot.cancellation.store(false, Ordering::Relaxed);
                slot.cleanup_errno.store(0, Ordering::Relaxed);
                slot.childless_inspector.store(
                    matches!(scope, CancellationScope::ChildlessInspector),
                    Ordering::Relaxed,
                );
                let ticket = Ticket {
                    inner: self.inner.clone(),
                    key,
                };
                if self.inner.closing.load(Ordering::Acquire) {
                    return Err(io::Error::other("native runtime closed during reservation"));
                }
                return Ok(ticket);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "native runtime capacity exhausted by retained obligations",
        ))
    }

    pub(crate) fn enqueue(&self, operation: Operation) -> io::Result<()> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(io::Error::other("native runtime is closing"));
        }
        self.inner
            .spawn
            .try_send(SpawnMessage::Work(operation))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "native creation queue is full or closed",
                )
            })
    }

    pub fn outstanding(&self) -> usize {
        self.inner
            .slots
            .iter()
            .filter(|slot| state(slot.state.load(Ordering::Acquire)) != State::Vacant as u64)
            .count()
    }
    #[cfg(feature = "test-support")]
    pub fn observer(&self) -> LaunchRuntimeObserver {
        LaunchRuntimeObserver {
            inner: self.inner.clone(),
        }
    }

    pub(crate) fn resolve_current_executable(
        &self,
    ) -> io::Result<mpsc::Receiver<io::Result<std::path::PathBuf>>> {
        let ticket = self.reserve()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        self.enqueue(Box::new(move || {
            let result = ticket.begin().and_then(|()| std::env::current_exe());
            let _ = sender.try_send(result);
            // A blocked filesystem lookup retains this reserved runtime slot.
            // Cancellation cannot create an unbounded replacement worker.
            drop(ticket);
        }))?;
        Ok(receiver)
    }
}

pub(crate) struct Ticket {
    inner: Arc<Inner>,
    key: SlotKey,
}

impl Ticket {
    fn slot(&self) -> &Slot {
        &self.inner.slots[self.key.index]
    }
    pub(crate) fn begin(&self) -> io::Result<()> {
        if self.inner.closing.load(Ordering::Acquire) {
            return Err(io::Error::other("native creation admission closed"));
        }
        self.transition(State::Reserved, State::Spawning)
    }
    fn transition(&self, from: State, to: State) -> io::Result<()> {
        self.slot()
            .state
            .compare_exchange(
                packed(self.key, from),
                packed(self.key, to),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| io::Error::other("native child ownership state changed"))
    }
    pub(crate) fn publish(&self, pid: i32) {
        assert!(pid > 0, "native spawn returned invalid child PID");
        self.slot().pid.store(pid, Ordering::Relaxed);
        self.transition(State::Spawning, State::Owned)
            .expect("exclusive spawn ticket publication");
    }
    pub(crate) fn complete(&self) -> io::Result<()> {
        self.transition(State::Owned, State::Complete)?;
        self.slot().pid.store(0, Ordering::Relaxed);
        self.transition(State::Complete, State::Vacant)?;
        let _ = self.inner.wake.try_send(());
        Ok(())
    }
    pub(crate) fn ownership_lost(&self, error: &io::Error) {
        self.slot()
            .cleanup_errno
            .store(error.raw_os_error().unwrap_or(libc::EIO), Ordering::Relaxed);
        let _ = self.transition(State::Owned, State::OwnershipLost);
        let _ = self.inner.wake.try_send(());
    }
    pub(crate) fn owns_child(&self) -> bool {
        self.slot().state.load(Ordering::Acquire) == packed(self.key, State::Owned)
    }
    pub(crate) fn pending(&self) -> bool {
        let value = self.slot().state.load(Ordering::Acquire);
        value >> STATE_BITS == self.key.generation && state(value) != State::Vacant as u64
    }
    pub(crate) fn observer(&self) -> RetirementObservation {
        RetirementObservation {
            inner: self.inner.clone(),
            key: self.key,
        }
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let slot = self.slot();
        let value = slot.state.load(Ordering::Acquire);
        if value == packed(self.key, State::Owned) {
            // Already allocated handoff storage; Drop never kills, waits, locks,
            // joins or allocates another queue node.
            slot.cancellation.store(true, Ordering::Relaxed);
            let _ = self.transition(State::Owned, State::Abandoned);
        } else if value == packed(self.key, State::Reserved)
            || value == packed(self.key, State::Spawning)
        {
            // No child has been published. The exclusive creation closure has
            // returned/unwound, so no native call remains active at this point.
            let _ = slot.state.compare_exchange(
                value,
                packed(self.key, State::Vacant),
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
        let _ = self.inner.wake.try_send(());
    }
}

pub(crate) struct RetirementObservation {
    inner: Arc<Inner>,
    key: SlotKey,
}
impl RetirementObservation {
    pub(crate) fn pending(&self) -> bool {
        let value = self.inner.slots[self.key.index]
            .state
            .load(Ordering::Acquire);
        value >> STATE_BITS == self.key.generation && state(value) != State::Vacant as u64
    }
    pub(crate) fn settled_until(&self, deadline: std::time::Instant) -> bool {
        loop {
            if !self.pending() {
                return true;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            std::thread::sleep(remaining.min(std::time::Duration::from_millis(2)));
        }
    }
}

fn reap(inner: Arc<Inner>, events: mpsc::Receiver<()>) {
    loop {
        let mut pending = false;
        for (index, slot) in inner.slots.iter().enumerate() {
            let value = slot.state.load(Ordering::Acquire);
            let current = state(value);
            if current == State::Vacant as u64 {
                continue;
            }
            pending = true;
            if current == State::OwnershipLost as u64 {
                continue;
            }
            let key = SlotKey {
                index,
                generation: value >> STATE_BITS,
            };
            if current == State::Abandoned as u64 {
                if slot
                    .state
                    .compare_exchange(
                        value,
                        packed(key, State::Reaping),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    continue;
                }
                let pid = slot.pid.load(Ordering::Acquire);
                if slot.cancellation.swap(false, Ordering::AcqRel) {
                    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
                    // Inspect actual wait ownership before using a numeric group
                    // identity. ECHILD means another waiter destroyed our pin.
                    let observed = unsafe {
                        libc::waitid(
                            libc::P_PID,
                            pid as libc::id_t,
                            info.as_mut_ptr(),
                            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                        )
                    };
                    if observed != 0 {
                        let error = io::Error::last_os_error();
                        if error.raw_os_error() == Some(libc::EINTR) {
                            slot.cancellation.store(true, Ordering::Release);
                            slot.state
                                .store(packed(key, State::Abandoned), Ordering::Release);
                        } else {
                            slot.cleanup_errno.store(
                                error.raw_os_error().unwrap_or(libc::EIO),
                                Ordering::Release,
                            );
                            slot.state
                                .store(packed(key, State::OwnershipLost), Ordering::Release);
                        }
                        continue;
                    }
                    // Childless inspectors require only the owned process to retire.
                    // Darwin may reject group signalling for an exited group leader.
                    let signal_target = if slot.childless_inspector.load(Ordering::Acquire) {
                        pid
                    } else {
                        -pid
                    };
                    // SAFETY: exclusive unreaped ownership pins the declared signal target.
                    if unsafe { libc::kill(signal_target, libc::SIGKILL) } != 0 {
                        let error = io::Error::last_os_error();
                        if error.raw_os_error() != Some(libc::ESRCH) {
                            slot.cleanup_errno.store(
                                error.raw_os_error().unwrap_or(libc::EIO),
                                Ordering::Release,
                            );
                        }
                    }
                }
            } else if current != State::Reaping as u64 {
                continue;
            }
            let pid = slot.pid.load(Ordering::Acquire);
            let mut status = 0;
            // SAFETY: only this worker owns a Reaping ticket and its child.
            let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if result == pid {
                slot.state
                    .store(packed(key, State::Complete), Ordering::Release);
                slot.pid.store(0, Ordering::Relaxed);
                // Keep an actual signalling error charged instead of calling
                // incomplete group cleanup a clean reusable obligation.
                slot.state.store(
                    packed(
                        key,
                        if slot.cleanup_errno.load(Ordering::Acquire) == 0 {
                            State::Vacant
                        } else {
                            State::OwnershipLost
                        },
                    ),
                    Ordering::Release,
                );
            } else if result < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EINTR) {
                    slot.cleanup_errno
                        .store(error.raw_os_error().unwrap_or(libc::EIO), Ordering::Relaxed);
                    slot.state
                        .store(packed(key, State::OwnershipLost), Ordering::Release);
                }
            }
        }
        if inner.closing.load(Ordering::Acquire) && !pending {
            break;
        }
        if pending {
            let _ = events.recv_timeout(Duration::from_millis(10));
        } else if events.recv().is_err() {
            break;
        }
    }
}
