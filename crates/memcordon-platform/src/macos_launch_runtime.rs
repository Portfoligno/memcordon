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

struct Slot {
    state: AtomicU64,
    pid: AtomicI32,
    cancellation: AtomicBool,
    cleanup_errno: AtomicI32,
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

    pub(crate) fn reserve(&self) -> io::Result<Ticket> {
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
                    // SAFETY: this exclusively owned unreaped group leader pins
                    // the process-group identity through this final signal.
                    if unsafe { libc::kill(-pid, libc::SIGKILL) } != 0 {
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
