//! Private native launch protocol. No target code runs before guardian arming.
use std::ffi::{CString, OsString};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use memcordon_core::CommandSpec;
use serde::{Deserialize, Serialize};

const STARTUP: Duration = Duration::from_secs(5);
const FRAME_LIMIT: usize = 4096;
const RESERVED: i32 = i32::MIN;
static CHILDREN: [AtomicI32; 256] = [const { AtomicI32::new(0) }; 256];
static DEPENDENCIES: [AtomicI32; 256] = [const { AtomicI32::new(0) }; 256];
static REAPER: OnceLock<Result<(), String>> = OnceLock::new();
type SpawnOperation = Box<dyn FnOnce() + Send>;
static SPAWNER: OnceLock<Result<std::sync::mpsc::SyncSender<SpawnOperation>, String>> =
    OnceLock::new();
#[cfg(feature = "test-support")]
std::thread_local! {
    static RUNNING_GUARDIAN_LOSS: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    static RUNNING_GUARDIAN_LOSS_FAILURE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    static RUNNING_GUARDIAN_LOSS_AT: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

/// Slots are reserved before spawn. Drop transfers an unreaped PID by one atomic
/// store to the permanent runtime, without allocation, locking, killing or waiting.
pub(crate) struct Child {
    pid: i32,
    slot: usize,
    status: Option<ExitStatus>,
    remote: Option<Arc<Mutex<Channel>>>,
}

fn reserve() -> io::Result<usize> {
    REAPER
        .get_or_init(|| {
            std::thread::Builder::new()
                .name("memcordon-native-reaper".into())
                .spawn(|| {
                    loop {
                        for (index, slot) in CHILDREN.iter().enumerate() {
                            let value = slot.load(Ordering::Acquire);
                            if value < 0 && value != RESERVED {
                                let dependency = DEPENDENCIES[index].load(Ordering::Acquire);
                                if dependency > 0
                                    && CHILDREN.iter().any(|entry| {
                                        entry.load(Ordering::Acquire).checked_abs()
                                            == Some(dependency)
                                    })
                                {
                                    continue;
                                }
                                let mut status = 0;
                                // SAFETY: only the runtime owns this abandoned, unreaped child.
                                let result =
                                    unsafe { libc::waitpid(-value, &mut status, libc::WNOHANG) };
                                if result > 0
                                    || (result < 0
                                        && io::Error::last_os_error().raw_os_error()
                                            == Some(libc::ECHILD))
                                {
                                    DEPENDENCIES[index].store(0, Ordering::Release);
                                    slot.store(0, Ordering::Release);
                                }
                            }
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                })
                .map(|_| ())
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| io::Error::other(error.clone()))?;
    CHILDREN
        .iter()
        .position(|slot| {
            slot.compare_exchange(0, RESERVED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })
        .ok_or_else(|| {
            io::Error::other("native reaper capacity exhausted by outstanding cleanup obligations")
        })
}

impl Child {
    pub(crate) fn id(&self) -> u32 {
        self.pid as u32
    }
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        if let Some(remote) = &self.remote {
            let mut channel = remote
                .lock()
                .map_err(|_| io::Error::other("guardian channel poisoned"))?;
            let deadline = Instant::now() + Duration::from_millis(100);
            channel.send(Message::Reap, deadline)?;
            return match channel.receive(deadline)? {
                Some(Message::Status { raw, reaped: true }) => {
                    self.status = raw.map(ExitStatus::from_raw);
                    Ok(self.status)
                }
                Some(Message::Status { reaped: false, .. }) => Ok(None),
                message => Err(io::Error::other(format!(
                    "guardian did not confirm target retirement: {message:?}"
                ))),
            };
        }
        let mut status = 0;
        // SAFETY: this handle owns the unreaped child and never waits synchronously.
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result == self.pid {
            self.status = Some(ExitStatus::from_raw(status));
            DEPENDENCIES[self.slot].store(0, Ordering::Release);
            CHILDREN[self.slot].store(0, Ordering::Release);
        }
        Ok(self.status)
    }
    pub(crate) fn observe(&self) -> io::Result<Option<ExitStatus>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        if let Some(remote) = &self.remote {
            let mut channel = remote
                .lock()
                .map_err(|_| io::Error::other("guardian channel poisoned"))?;
            let deadline = Instant::now() + Duration::from_millis(100);
            channel.send(Message::Observe, deadline)?;
            return match channel.receive(deadline)? {
                Some(Message::Status { raw, .. }) => Ok(raw.map(ExitStatus::from_raw)),
                _ => Err(io::Error::other("guardian target observation unavailable")),
            };
        }
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: WNOWAIT pins the child's identity until workload signalling ends.
        if unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid as libc::id_t,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful waitid initialized the supplied siginfo storage.
        let info = unsafe { info.assume_init() };
        if info.si_pid == 0 {
            return Ok(None);
        }
        let raw = match info.si_code {
            libc::CLD_EXITED => info.si_status << 8,
            libc::CLD_KILLED => info.si_status,
            libc::CLD_DUMPED => info.si_status | 0x80,
            _ => return Err(io::Error::other("unexpected child observation code")),
        };
        Ok(Some(ExitStatus::from_raw(raw)))
    }
    pub(crate) fn kill(&self) -> io::Result<()> {
        if self.status.is_some() {
            return Ok(());
        }
        if let Some(remote) = &self.remote {
            let mut channel = remote
                .lock()
                .map_err(|_| io::Error::other("guardian channel poisoned"))?;
            return channel.send(Message::Stop, Instant::now() + Duration::from_millis(100));
        }
        // SAFETY: the unreaped owned leader pins this dedicated process group.
        if unsafe { libc::kill(-self.pid, libc::SIGKILL) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }
    pub(crate) fn retire(&mut self, deadline: Instant) -> io::Result<()> {
        loop {
            if self.try_wait()?.is_some() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child remains an owned reaping obligation",
                ));
            }
            std::thread::sleep(
                Duration::from_millis(5).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.status.is_none() && self.remote.is_none() {
            CHILDREN[self.slot].store(-self.pid, Ordering::Release);
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Message {
    Hello,
    Ready,
    Bind {
        group: i32,
    },
    Armed {
        group: i32,
    },
    Release,
    Disarm,
    Retired,
    Failure {
        errno: i32,
    },
    FailureDetail {
        message: String,
    },
    #[cfg(feature = "test-support")]
    HoldSpawn,
    #[cfg(feature = "test-support")]
    HoldSpawnReleaseAfterCancel,
    #[cfg(feature = "test-support")]
    SpawnHeld {
        pid: i32,
    },
    #[cfg(feature = "test-support")]
    ResumeSpawn,
    #[cfg(feature = "test-support")]
    InterruptClock,
    #[cfg(feature = "test-support")]
    ClockInterruptible,
    #[cfg(feature = "test-support")]
    AdvanceClock {
        nanos: u64,
    },
    #[cfg(feature = "test-support")]
    DisableWorkTimer,
    Configure {
        image: Vec<u8>,
        boot_identity: String,
        startup: u64,
        work: Option<u64>,
        grace: u64,
    },
    Prepared {
        pid: i32,
    },
    Released,
    ReleaseIssued {
        at: u64,
    },
    ForceRequested {
        at: u64,
    },
    Observe,
    Reap,
    Stop,
    Heartbeat,
    StopAt {
        force: u64,
    },
    SignalStop {
        signal: i32,
        force: u64,
    },
    RestoreSignal {
        settings: crate::macos_envelope::Settings,
    },
    InventoryQuery {
        query: u64,
        metric: Option<memcordon_core::Metric>,
    },
    InventoryChunk {
        query: u64,
        bytes: Vec<u8>,
        finished: bool,
    },
    Status {
        raw: Option<i32>,
        reaped: bool,
    },
    #[cfg(feature = "test-support")]
    StallInspectors {
        both: bool,
    },
    #[cfg(feature = "test-support")]
    InspectorsStalled {
        normal: u32,
        emergency: u32,
    },
    #[cfg(feature = "test-support")]
    Snapshot {
        pid: i32,
    },
    #[cfg(feature = "test-support")]
    Observed {
        pid: i32,
        observed: bool,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    version: u8,
    run: u64,
    sequence: u64,
    message: Message,
}

struct Channel {
    stream: UnixStream,
    run: u64,
    sent: u64,
    received: u64,
    input: Vec<u8>,
    inventory_query: Option<u64>,
    force_receipt: Arc<std::sync::atomic::AtomicU64>,
}

fn private_pair() -> io::Result<(UnixStream, UnixStream)> {
    let (left, right) = UnixStream::pair()?;
    let promote = |stream: UnixStream| {
        // SAFETY: duplicate above stdio with CLOEXEC before closing the temporary endpoint.
        let descriptor = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this newly duplicated descriptor is uniquely owned.
        Ok(unsafe { UnixStream::from_raw_fd(descriptor) })
    };
    Ok((promote(left)?, promote(right)?))
}

struct ExecWitness(std::os::fd::OwnedFd);
impl ExecWitness {
    fn new(pid: i32) -> io::Result<Self> {
        // SAFETY: kqueue creates a new owned descriptor.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this unique descriptor is consumed into OwnedFd.
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        // SAFETY: only this internal descriptor gets close-on-exec.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let event = libc::kevent {
            ident: pid as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: libc::NOTE_EXEC | libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: register an unreaped owned, still-gated child's native exec event.
        if unsafe { libc::kevent(fd, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(owned))
    }
    fn confirm(&self, deadline: Instant) -> io::Result<()> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "target exec was not confirmed by the kernel",
                ));
            }
            let timeout = libc::timespec {
                tv_sec: remaining.as_secs() as libc::time_t,
                tv_nsec: remaining.subsec_nanos() as libc::c_long,
            };
            let mut event = std::mem::MaybeUninit::<libc::kevent>::zeroed();
            // SAFETY: one event output and a bounded native timeout are supplied.
            let count = unsafe {
                libc::kevent(
                    self.0.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    event.as_mut_ptr(),
                    1,
                    &timeout,
                )
            };
            if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            if count == 0 {
                continue;
            }
            // SAFETY: kevent initialized the single returned event.
            let event = unsafe { event.assume_init() };
            if event.fflags & libc::NOTE_EXEC != 0 {
                return Ok(());
            }
            return Err(io::Error::other(
                "launcher exited without a kernel exec observation",
            ));
        }
    }
}
impl Channel {
    fn new(stream: UnixStream, run: u64) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        let value: libc::c_int = 1;
        // SAFETY: SO_NOSIGPIPE changes only this private owned socket.
        if unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            stream,
            run,
            sent: 0,
            received: 0,
            input: Vec::new(),
            inventory_query: None,
            force_receipt: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }
    fn transfer(&mut self, bytes: &mut [u8], write: bool, deadline: Instant) -> io::Result<bool> {
        let mut offset = 0;
        while offset < bytes.len() {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "private launch protocol deadline expired",
                ));
            }
            let result = if write {
                self.stream.write(&bytes[offset..])
            } else {
                self.stream.read(&mut bytes[offset..])
            };
            match result {
                Ok(0) if !write && offset == 0 => return Ok(false),
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "partial private launch frame",
                    ));
                }
                Ok(count) => offset += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut poll = libc::pollfd {
                        fd: self.stream.as_raw_fd(),
                        events: if write { libc::POLLOUT } else { libc::POLLIN },
                        revents: 0,
                    };
                    let wait = deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .min(50) as i32;
                    // SAFETY: poll receives one live owned socket and a bounded timeout.
                    if unsafe { libc::poll(&mut poll, 1, wait) } < 0
                        && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(true)
    }
    fn send(&mut self, message: Message, deadline: Instant) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(&Frame {
            version: 2,
            run: self.run,
            sequence: self.sent,
            message,
        })?;
        if bytes.len() > FRAME_LIMIT {
            return Err(io::Error::other("private launch frame exceeds bound"));
        }
        self.transfer(&mut (bytes.len() as u16).to_be_bytes(), true, deadline)?;
        self.transfer(&mut bytes, true, deadline)?;
        self.sent = self
            .sent
            .checked_add(1)
            .ok_or_else(|| io::Error::other("protocol sequence exhausted"))?;
        Ok(())
    }
    fn receive(&mut self, deadline: Instant) -> io::Result<Option<Message>> {
        loop {
            match self.receive_available()? {
                Some(Some(Message::ForceRequested { at })) => {
                    self.force_receipt
                        .compare_exchange(0, at, Ordering::AcqRel, Ordering::Acquire)
                        .ok();
                }
                Some(Some(Message::InventoryChunk { query, .. }))
                    if self.inventory_query != Some(query) =>
                {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "discarded inventory exceeded control deadline",
                        ));
                    }
                    continue;
                }
                Some(message) => return Ok(message),
                None => {}
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "private protocol deadline expired",
                ));
            }
            let mut poll = libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .clamp(1, 20) as i32;
            // SAFETY: one owned socket and finite wait.
            if unsafe { libc::poll(&mut poll, 1, wait) } < 0
                && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                return Err(io::Error::last_os_error());
            }
        }
    }
    /// One bounded read; partial frames remain parser state between timer turns.
    fn receive_available(&mut self) -> io::Result<Option<Option<Message>>> {
        let mut bytes = [0_u8; FRAME_LIMIT + std::mem::size_of::<u16>()];
        let capacity = bytes.len().saturating_sub(self.input.len());
        if capacity == 0 {
            return Err(io::Error::other("private frame exceeds bound"));
        }
        let mut eof = false;
        match self.stream.read(&mut bytes[..capacity]) {
            Ok(0) if self.input.is_empty() => return Ok(Some(None)),
            Ok(0) => eof = true,
            Ok(count) => self.input.extend_from_slice(&bytes[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
        let prefix = std::mem::size_of::<u16>();
        if self.input.len() < prefix {
            if eof {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "partial private frame",
                ));
            }
            return Ok(None);
        }
        let length = usize::from(u16::from_be_bytes(
            self.input[..prefix].try_into().expect("prefix length"),
        ));
        if length == 0 || length > FRAME_LIMIT {
            return Err(io::Error::other("invalid private frame length"));
        }
        if self.input.len() < prefix + length {
            if eof {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "partial private frame",
                ));
            }
            return Ok(None);
        }
        let frame: Frame = serde_json::from_slice(&self.input[prefix..prefix + length])?;
        if frame.version != 2 || frame.run != self.run || frame.sequence != self.received {
            return Err(io::Error::other(
                "private protocol binding or sequence mismatch",
            ));
        }
        self.received = self
            .received
            .checked_add(1)
            .ok_or_else(|| io::Error::other("protocol sequence exhausted"))?;
        self.input.drain(..prefix + length);
        Ok(Some(Some(frame.message)))
    }
    fn expect(&mut self, expected: Message, deadline: Instant) -> io::Result<()> {
        match self.receive(deadline)? {
            Some(message) if message == expected => Ok(()),
            Some(Message::Failure { errno }) => Err(io::Error::from_raw_os_error(errno)),
            _ => Err(io::Error::other(
                "unexpected private launch protocol transition",
            )),
        }
    }
}

fn native_spawn(
    path: &Path,
    args: &[OsString],
    endpoint: RawFd,
    quiet: bool,
    deadline: Instant,
) -> io::Result<Child> {
    native_spawn_context(path, args, endpoint, quiet, deadline, None, None)
}

fn native_spawn_context(
    path: &Path,
    args: &[OsString],
    endpoint: RawFd,
    quiet: bool,
    deadline: Instant,
    context: Option<crate::macos_envelope::Envelope>,
    auxiliary: Option<(RawFd, std::os::fd::OwnedFd)>,
) -> io::Result<Child> {
    let expires = crate::macos_deadline::add(
        crate::macos_deadline::continuous_nanos()?,
        deadline.saturating_duration_since(Instant::now()),
    )?;
    // Use distinct source/destination descriptors: Darwin's same-fd spawn action
    // does not reliably remove close-on-exec from a std-created socket.
    // SAFETY: this duplicates only the private endpoint and retains CLOEXEC in the parent.
    let source = unsafe { libc::fcntl(endpoint, libc::F_DUPFD_CLOEXEC, 3) };
    if source < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the new duplicate is uniquely owned until spawn finishes.
    let source = unsafe { std::os::fd::OwnedFd::from_raw_fd(source) };
    let path = path.to_owned();
    let args = args.to_vec();
    let environment = std::env::vars_os().collect::<Vec<_>>();
    let worker = SPAWNER
        .get_or_init(|| {
            let (send, receive) = std::sync::mpsc::sync_channel::<SpawnOperation>(1);
            std::thread::Builder::new()
                .name("memcordon-native-spawn".into())
                .spawn(move || {
                    while let Ok(operation) = receive.recv() {
                        operation();
                    }
                })
                .map_err(|error| error.to_string())?;
            Ok(send)
        })
        .as_ref()
        .map_err(|error| io::Error::other(error.clone()))?;
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    worker
        .try_send(Box::new(move || {
            if Instant::now() >= deadline {
                return;
            }
            let result = native_spawn_owned(
                &path,
                &args,
                endpoint,
                quiet,
                source,
                environment,
                SpawnEnvelope {
                    context,
                    auxiliary,
                    target: false,
                },
            );
            let _ = send.send(result);
        }))
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "native spawn slot busy"))?;
    loop {
        if crate::macos_deadline::continuous_nanos()? >= expires {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native creation remains owned in flight",
            ));
        }
        match receive.recv_timeout(Duration::from_millis(2)) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("native creation owner unavailable"));
            }
        }
    }
}

struct SpawnEnvelope {
    context: Option<crate::macos_envelope::Envelope>,
    auxiliary: Option<(RawFd, std::os::fd::OwnedFd)>,
    target: bool,
}

fn native_spawn_owned(
    path: &Path,
    args: &[OsString],
    endpoint: RawFd,
    quiet: bool,
    source: std::os::fd::OwnedFd,
    environment: Vec<(OsString, OsString)>,
    envelope: SpawnEnvelope,
) -> io::Result<Child> {
    let SpawnEnvelope {
        context,
        auxiliary,
        target,
    } = envelope;
    let source = if let Some(context) = &context {
        crate::macos_envelope::duplicate(
            source.as_raw_fd(),
            context.private_floor()?.max(endpoint.saturating_add(1)),
        )?
    } else {
        source
    };
    let image = CString::new(path.as_os_str().as_bytes())?;
    let arguments = std::iter::once(path.as_os_str())
        .chain(args.iter().map(OsString::as_os_str))
        .map(|arg| CString::new(arg.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv = arguments
        .iter()
        .map(|arg| arg.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null_mut());
    let environment = environment
        .into_iter()
        .map(|(key, value)| {
            let mut item = key.into_vec();
            item.push(b'=');
            item.extend_from_slice(value.as_bytes());
            CString::new(item)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut envp = environment
        .iter()
        .map(|item| item.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    envp.push(std::ptr::null_mut());
    let slot = reserve()?;
    let result = (|| {
        let mut actions = std::mem::MaybeUninit::<libc::posix_spawn_file_actions_t>::uninit();
        let mut attributes = std::mem::MaybeUninit::<libc::posix_spawnattr_t>::uninit();
        // SAFETY: initialization APIs receive writable native objects, destroyed on all initialized paths.
        unsafe {
            check(libc::posix_spawn_file_actions_init(actions.as_mut_ptr()))?;
            let mut actions = actions.assume_init();
            let initialized = libc::posix_spawnattr_init(attributes.as_mut_ptr());
            if initialized != 0 {
                libc::posix_spawn_file_actions_destroy(&mut actions);
                return Err(io::Error::from_raw_os_error(initialized));
            }
            let mut attributes = attributes.assume_init();
            let result = (|| {
                check(libc::posix_spawn_file_actions_adddup2(
                    &mut actions,
                    source.as_raw_fd(),
                    endpoint,
                ))?;
                if let Some((destination, source)) = &auxiliary {
                    check(libc::posix_spawn_file_actions_adddup2(
                        &mut actions,
                        source.as_raw_fd(),
                        *destination,
                    ))?;
                }
                if quiet {
                    let limit = libc::getdtablesize();
                    if !(0..=1_048_576).contains(&limit) {
                        return Err(io::Error::other("helper descriptor envelope exceeds bound"));
                    }
                    for fd in 3..limit {
                        let flags = libc::fcntl(fd, libc::F_GETFD);
                        if fd != endpoint
                            && fd != source.as_raw_fd()
                            && !auxiliary
                                .as_ref()
                                .is_some_and(|(destination, _)| *destination == fd)
                            && flags >= 0
                            && flags & libc::FD_CLOEXEC == 0
                        {
                            check(libc::posix_spawn_file_actions_addclose(&mut actions, fd))?;
                        }
                    }
                    for fd in [0, 1, 2] {
                        check(libc::posix_spawn_file_actions_addopen(
                            &mut actions,
                            fd,
                            c"/dev/null".as_ptr(),
                            libc::O_RDWR,
                            0,
                        ))?;
                    }
                }
                if let Some(context) = &context {
                    context.actions(&mut actions, &mut attributes, target)?;
                }
                check(libc::posix_spawn_file_actions_addclose(
                    &mut actions,
                    source.as_raw_fd(),
                ))?;
                if let Some((_, source)) = &auxiliary {
                    check(libc::posix_spawn_file_actions_addclose(
                        &mut actions,
                        source.as_raw_fd(),
                    ))?;
                }
                check(libc::posix_spawnattr_setpgroup(&mut attributes, 0))?;
                check(libc::posix_spawnattr_setflags(
                    &mut attributes,
                    (libc::POSIX_SPAWN_SETPGROUP
                        | libc::POSIX_SPAWN_CLOEXEC_DEFAULT
                        | if context.is_some() {
                            libc::POSIX_SPAWN_SETSIGMASK
                        } else {
                            0
                        }) as i16,
                ))?;
                let mut pid = 0;
                check(libc::posix_spawn(
                    &mut pid,
                    image.as_ptr(),
                    &actions,
                    &attributes,
                    argv.as_ptr(),
                    envp.as_ptr(),
                ))?;
                Ok(pid)
            })();
            libc::posix_spawnattr_destroy(&mut attributes);
            libc::posix_spawn_file_actions_destroy(&mut actions);
            result
        }
    })();
    match result {
        Ok(pid) => {
            CHILDREN[slot].store(pid, Ordering::Release);
            Ok(Child {
                pid,
                slot,
                status: None,
                remote: None,
            })
        }
        Err(error) => {
            CHILDREN[slot].store(0, Ordering::Release);
            Err(error)
        }
    }
}

fn check(code: i32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code))
    }
}

pub(crate) struct Guardian {
    channel: Option<Arc<Mutex<Channel>>>,
    child: Child,
}
impl Guardian {
    pub(crate) fn force_receipt(&self) -> io::Result<Arc<std::sync::atomic::AtomicU64>> {
        Ok(self
            .channel
            .as_ref()
            .ok_or_else(|| io::Error::other("guardian lease unavailable"))?
            .lock()
            .map_err(|_| io::Error::other("guardian channel poisoned"))?
            .force_receipt
            .clone())
    }
    pub(crate) fn signal_stop(&self, signal: i32, grace: Duration) -> io::Result<()> {
        let force = crate::macos_deadline::add(crate::macos_deadline::continuous_nanos()?, grace)?;
        self.channel
            .as_ref()
            .ok_or_else(|| io::Error::other("guardian lease unavailable"))?
            .lock()
            .map_err(|_| io::Error::other("guardian channel poisoned"))?
            .send(
                Message::SignalStop { signal, force },
                Instant::now() + Duration::from_millis(20),
            )
    }
    fn query(
        &self,
        metric: Option<memcordon_core::Metric>,
        deadline: Instant,
    ) -> Result<InventoryReply, String> {
        let mut channel = self
            .channel
            .as_ref()
            .ok_or("guardian lease unavailable")?
            .lock()
            .map_err(|_| "guardian channel poisoned")?;
        let query = channel.sent;
        channel
            .send(Message::InventoryQuery { query, metric }, deadline)
            .map_err(|error| error.to_string())?;
        channel.inventory_query = Some(query);
        let result = (|| {
            let mut payload = Vec::new();
            loop {
                if Instant::now() >= deadline {
                    return Err("guardian inventory deadline expired".into());
                }
                let message = channel
                    .receive(deadline)
                    .map_err(|error| error.to_string())?;
                match message {
                    Some(Message::InventoryChunk {
                        bytes, finished, ..
                    }) => {
                        if bytes.len() > 512
                            || payload.len().saturating_add(bytes.len()) > INVENTORY_FRAME_LIMIT
                        {
                            return Err("guardian inventory response exceeds bound".into());
                        }
                        payload.extend(bytes);
                        if finished {
                            return serde_json::from_slice(&payload)
                                .map_err(|error| error.to_string());
                        }
                    }
                    Some(Message::FailureDetail { message }) => return Err(message),
                    other => {
                        return Err(format!("unexpected guardian inventory response: {other:?}"));
                    }
                }
            }
        })();
        channel.inventory_query = None;
        result
    }
    pub(crate) fn inventory(
        &self,
        deadline: Instant,
    ) -> Result<
        (
            Vec<crate::macos_watchdog::ProcessSnapshot>,
            InventoryIdentities,
        ),
        String,
    > {
        let (snapshots, known, _) = self.query(None, deadline)?;
        snapshots.map(|snapshots| (snapshots, known))
    }
    pub(crate) fn sample(
        &self,
        metric: memcordon_core::Metric,
        deadline: Instant,
    ) -> Result<u64, String> {
        let (_, _, sample) = self.query(Some(metric), deadline)?;
        sample.ok_or_else(|| "guardian sample response missing".to_owned())?
    }
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }
    pub(crate) fn alive(&self) -> io::Result<()> {
        if let Some(channel) = &self.channel {
            channel
                .lock()
                .map_err(|_| io::Error::other("guardian channel poisoned"))?
                .send(
                    Message::Heartbeat,
                    Instant::now() + Duration::from_millis(20),
                )?;
        }
        if self.child.observe()?.is_none() {
            Ok(())
        } else {
            Err(io::Error::other(
                "guardian exited before workload retirement",
            ))
        }
    }
    pub(crate) fn disarm(mut self, deadline: Instant) -> io::Result<()> {
        let shared = self.channel.take().expect("live guardian lease");
        let mut channel = shared
            .lock()
            .map_err(|_| io::Error::other("guardian channel poisoned"))?;
        channel.send(Message::Disarm, deadline)?;
        channel.expect(Message::Retired, deadline)?;
        drop(channel);
        self.child.retire(deadline)
    }
}

pub(crate) struct Launch {
    pub(crate) child: Child,
    pub(crate) guardian: Guardian,
    pub(crate) release_tick: u64,
}
pub(crate) struct StartupError {
    pub(crate) phase: &'static str,
    pub(crate) error: io::Error,
    pub(crate) diagnostic: memcordon_core::NativeStartupDiagnosticV1,
    pub(crate) release: memcordon_core::ReleaseEvidence,
}

#[derive(Clone, Copy, PartialEq)]
pub enum LaunchFault {
    GuardianBeforeArm,
    GuardianAfterArm,
    LauncherBeforeExec,
    #[cfg(feature = "test-support")]
    NativeSpawnHeld,
    #[cfg(feature = "test-support")]
    NativeSpawnHeldReleaseAfterCancel,
}

pub(crate) fn launch(
    command: &CommandSpec,
    image: &Path,
    deadline: Instant,
    cleanup_deadline: Instant,
) -> Result<Launch, Box<StartupError>> {
    launch_with_deadline(
        command,
        image,
        deadline,
        cleanup_deadline,
        None,
        Duration::ZERO,
    )
}

pub(crate) fn launch_with_deadline(
    command: &CommandSpec,
    image: &Path,
    deadline: Instant,
    cleanup_deadline: Instant,
    work: Option<u64>,
    grace: Duration,
) -> Result<Launch, Box<StartupError>> {
    launch_configured(
        command,
        image,
        deadline,
        cleanup_deadline,
        None,
        work,
        grace,
    )
}

fn launch_inner(
    command: &CommandSpec,
    image: &Path,
    deadline: Instant,
    cleanup_deadline: Instant,
    fault: Option<LaunchFault>,
) -> Result<Launch, Box<StartupError>> {
    launch_configured(
        command,
        image,
        deadline,
        cleanup_deadline,
        fault,
        None,
        Duration::ZERO,
    )
}

fn launch_configured(
    command: &CommandSpec,
    image: &Path,
    deadline: Instant,
    cleanup_deadline: Instant,
    fault: Option<LaunchFault>,
    work: Option<u64>,
    grace: Duration,
) -> Result<Launch, Box<StartupError>> {
    use memcordon_core::{
        NativeArgument, NativeStartupCleanupErrorV1, NativeStartupCleanupStateV1 as CleanupState,
        NativeStartupCleanupV1, NativeStartupDiagnosticV1, NativeStartupOperationV1 as Operation,
        NativeStartupPhaseV1 as Phase,
    };
    let mut diagnostic = NativeStartupDiagnosticV1 {
        schema_version: 1,
        requested_helper: NativeArgument::from_os(image.as_os_str()),
        canonical_helper: None,
        helper_identity: None,
        cwd: None,
        phase: Phase::GuardianSpawn,
        operation: Operation::SpawnGuardian,
        native_errno: None,
        guardian_pid: None,
        guardian_ready: false,
        launcher_pid: None,
        release_sent: false,
        exec_confirmed: false,
        cleanup: NativeStartupCleanupV1 {
            state: CleanupState::Unknown,
            errors: Vec::new(),
        },
    };
    let mut guardian_owner = None;
    let mut configured = false;
    let mut release = memcordon_core::ReleaseEvidence::NotIssued;
    let mut phase = "helper-spawn";
    if Instant::now() >= deadline {
        diagnostic.cleanup.state = CleanupState::Complete;
        return Err(Box::new(StartupError {
            phase,
            error: io::Error::new(io::ErrorKind::TimedOut, "startup expired before creation"),
            diagnostic,
            release,
        }));
    }
    let result = (|| {
        let mut run = 0_u64;
        // SAFETY: initializes the exact local run binding.
        unsafe { libc::arc4random_buf((&mut run as *mut u64).cast(), std::mem::size_of_val(&run)) };
        let now = crate::macos_deadline::continuous_nanos()?;
        let startup =
            crate::macos_deadline::add(now, deadline.saturating_duration_since(Instant::now()))?;
        let envelope = crate::macos_envelope::Envelope::capture_bounded(deadline)?;
        let (envelope_send, envelope_receive) = std::os::unix::net::UnixDatagram::pair()?;
        envelope.send(&envelope_send, run)?;
        let auxiliary = (
            envelope_receive.as_raw_fd(),
            crate::macos_envelope::duplicate(envelope_receive.as_raw_fd(), 3)?,
        );
        let (parent, endpoint) = private_pair()?;
        let channel = Arc::new(Mutex::new(Channel::new(parent, run)?));
        let mut args = vec![
            OsString::from("__macos-guardian-envelope-v1"),
            endpoint.as_raw_fd().to_string().into(),
            run.to_string().into(),
            envelope_receive.as_raw_fd().to_string().into(),
            OsString::from("--"),
            command.program().to_owned(),
        ];
        args.extend(command.arguments().iter().cloned());
        let child = native_spawn_context(
            image,
            &args,
            endpoint.as_raw_fd(),
            true,
            deadline,
            Some(envelope),
            Some(auxiliary),
        )?;
        diagnostic.guardian_pid = Some(child.id());
        drop(endpoint);
        guardian_owner = Some(Guardian {
            channel: Some(channel.clone()),
            child,
        });
        let guardian = guardian_owner.as_mut().expect("guardian created");
        let mut control = channel
            .lock()
            .map_err(|_| io::Error::other("guardian channel poisoned"))?;
        phase = "helper-ready";
        diagnostic.phase = Phase::GuardianReadiness;
        diagnostic.operation = Operation::ReadGuardianReadiness;
        control.expect(Message::Hello, deadline)?;
        #[cfg(feature = "test-support")]
        if fault == Some(LaunchFault::NativeSpawnHeld) {
            control.send(Message::HoldSpawn, deadline)?;
        }
        #[cfg(feature = "test-support")]
        if fault == Some(LaunchFault::NativeSpawnHeldReleaseAfterCancel) {
            control.send(Message::HoldSpawnReleaseAfterCancel, deadline)?;
        }
        control.send(
            Message::Configure {
                image: image.as_os_str().as_bytes().to_vec(),
                boot_identity: crate::macos_deadline::boot_identity()?,
                startup,
                work,
                grace: u64::try_from(grace.as_nanos())
                    .map_err(|_| io::Error::other("grace range exceeded"))?,
            },
            deadline,
        )?;
        configured = true;
        control.expect(Message::Ready, deadline)?;
        diagnostic.guardian_ready = true;
        #[cfg(feature = "test-support")]
        if matches!(
            fault,
            Some(LaunchFault::NativeSpawnHeld | LaunchFault::NativeSpawnHeldReleaseAfterCancel)
        ) {
            match control.receive(deadline)? {
                Some(Message::SpawnHeld { pid }) if pid > 0 => {
                    diagnostic.launcher_pid = Some(pid as u32)
                }
                _ => return Err(io::Error::other("native spawn hold receipt missing")),
            }
            // The phase receipt proves native creation completed. Keep publication
            // withheld across the original admission boundary before releasing it.
            while Instant::now() < deadline {
                std::thread::sleep(
                    Duration::from_millis(10)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            control.send(Message::ResumeSpawn, cleanup_deadline)?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "held native spawn publication expired",
            ));
        }
        if fault == Some(LaunchFault::GuardianBeforeArm) {
            guardian.child.kill()?;
        }
        phase = "launcher-spawn";
        diagnostic.phase = Phase::LauncherSpawn;
        diagnostic.operation = Operation::SpawnLauncher;
        let pid = match control.receive(deadline)? {
            Some(Message::Prepared { pid }) if pid > 0 => pid,
            Some(Message::Failure { errno }) => return Err(io::Error::from_raw_os_error(errno)),
            _ => return Err(io::Error::other("guardian preparation receipt invalid")),
        };
        diagnostic.launcher_pid = Some(pid as u32);
        if fault == Some(LaunchFault::GuardianAfterArm) {
            guardian.child.kill()?;
        }
        if fault == Some(LaunchFault::LauncherBeforeExec) {
            control.send(Message::Stop, deadline)?;
        }
        phase = "target-release";
        diagnostic.phase = Phase::TargetRelease;
        diagnostic.operation = Operation::ReleaseTarget;
        control.send(Message::Release, deadline)?;
        // A sent request without its receipt is uncertain, never known not-issued.
        release = memcordon_core::ReleaseEvidence::Unknown;
        match control.receive(deadline)? {
            Some(Message::ReleaseIssued { at }) => {
                release = memcordon_core::ReleaseEvidence::Issued {
                    at,
                    exec_confirmed: false,
                };
                diagnostic.release_sent = true;
            }
            _ => return Err(io::Error::other("guardian release receipt unavailable")),
        }
        phase = "target-exec";
        diagnostic.phase = Phase::TargetExec;
        diagnostic.operation = Operation::ConfirmTargetExec;
        control.expect(Message::Released, deadline)?;
        diagnostic.exec_confirmed = true;
        #[cfg(feature = "test-support")]
        if RUNNING_GUARDIAN_LOSS.get() == Some(0) {
            RUNNING_GUARDIAN_LOSS.set(Some(pid));
            RUNNING_GUARDIAN_LOSS_AT.set(Some(Instant::now()));
            guardian.child.kill()?;
            guardian
                .child
                .retire(Instant::now() + Duration::from_secs(1))?;
        }
        if let memcordon_core::ReleaseEvidence::Issued { exec_confirmed, .. } = &mut release {
            *exec_confirmed = true;
        }
        drop(control);
        Ok(Child {
            pid,
            slot: 0,
            status: None,
            remote: Some(channel),
        })
    })();
    match result {
        Ok(child) => Ok(Launch {
            child,
            guardian: guardian_owner.take().expect("successful guardian"),
            release_tick: match release {
                memcordon_core::ReleaseEvidence::Issued { at, .. } => at,
                _ => unreachable!("confirmed grant"),
            },
        }),
        Err(error) => {
            #[cfg(feature = "test-support")]
            if RUNNING_GUARDIAN_LOSS.get() == Some(0) {
                RUNNING_GUARDIAN_LOSS_FAILURE.with_borrow_mut(|failure| {
                    *failure = Some(format!("{phase}: {error}; {diagnostic:?}"))
                });
            }
            diagnostic.native_errno = error.raw_os_error();
            if let Some(guardian) = guardian_owner.as_mut() {
                // Closing the final frontend lease transfers cleanup to the actual native parent.
                guardian.channel.take();
                if !configured {
                    let _ = guardian.child.kill();
                }
                match guardian.child.retire(cleanup_deadline) {
                    Ok(())
                        if !configured
                            || guardian.child.status.is_some_and(|status| status.success()) =>
                    {
                        diagnostic.cleanup.state = CleanupState::Complete
                    }
                    Ok(()) => {}
                    Err(error) => diagnostic.cleanup.errors.push(NativeStartupCleanupErrorV1 {
                        operation: Operation::ReapGuardian,
                        native_errno: error.raw_os_error(),
                        detail: error.to_string(),
                    }),
                }
            } else if error.kind() != io::ErrorKind::TimedOut {
                diagnostic.cleanup.state = CleanupState::Complete;
            }
            if !diagnostic.cleanup.errors.is_empty() {
                diagnostic.cleanup.state = CleanupState::Incomplete;
            }
            Err(Box::new(StartupError {
                phase,
                error,
                diagnostic,
                release,
            }))
        }
    }
}

fn exec_native(program: &std::ffi::OsStr, arguments: &[OsString]) -> io::Error {
    let arguments = std::iter::once(program)
        .chain(arguments.iter().map(OsString::as_os_str))
        .map(|argument| CString::new(argument.as_bytes()))
        .collect::<Result<Vec<_>, _>>();
    let Ok(arguments) = arguments else {
        return io::Error::from_raw_os_error(libc::EINVAL);
    };
    let mut argv = arguments
        .iter()
        .map(|argument| argument.as_ptr())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null());
    let paths = if program.as_bytes().contains(&b'/') {
        vec![std::path::PathBuf::from(program)]
    } else {
        std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin")),
        )
        .map(|directory| directory.join(program))
        .collect()
    };
    let mut denied = false;
    for path in paths {
        let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
            return io::Error::from_raw_os_error(libc::EINVAL);
        };
        // SAFETY: NUL-terminated native path and argv remain owned throughout exec.
        unsafe { libc::execv(path.as_ptr(), argv.as_ptr()) };
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EACCES) => denied = true,
            Some(libc::ENOENT | libc::ENOTDIR) => {}
            _ => return error,
        }
    }
    io::Error::from_raw_os_error(if denied { libc::EACCES } else { libc::ENOENT })
}

type InventoryIdentities = std::collections::HashSet<crate::macos_watchdog::ProcessIdentity>;
type InventoryReply = (
    Result<Vec<crate::macos_watchdog::ProcessSnapshot>, String>,
    InventoryIdentities,
    Option<Result<u64, String>>,
);
type InventoryRequest = (
    i32,
    InventoryIdentities,
    Option<i32>,
    Option<memcordon_core::Metric>,
);

fn normalize_inventory_sample(reply: &mut InventoryReply) {
    if reply.0.as_ref().is_ok_and(|members| members.is_empty()) {
        reply.2 = Some(Ok(0));
    }
}

fn inventory_answers_query(
    requested: Option<memcordon_core::Metric>,
    sampled: Option<memcordon_core::Metric>,
    empty: bool,
    has_sample: bool,
) -> bool {
    requested.is_none() || empty || (requested == sampled && has_sample)
}

#[cfg(feature = "test-support")]
pub fn empty_inventory_query_transition(
    requested: Option<memcordon_core::Metric>,
    sampled: Option<memcordon_core::Metric>,
    authoritative: bool,
) -> (bool, Option<Result<u64, String>>) {
    let mut reply: InventoryReply = (Ok(Vec::new()), InventoryIdentities::new(), None);
    normalize_inventory_sample(&mut reply);
    let encoded = serde_json::to_vec(&reply).expect("bounded empty inventory");
    let decoded: InventoryReply = serde_json::from_slice(&encoded).expect("encoded inventory");
    let answered =
        authoritative && inventory_answers_query(requested, sampled, true, decoded.2.is_some());
    (answered, decoded.2)
}

#[cfg(feature = "test-support")]
pub fn nonempty_inventory_query_transition(
    requested: Option<memcordon_core::Metric>,
    sampled: Option<memcordon_core::Metric>,
    has_sample: bool,
) -> bool {
    inventory_answers_query(requested, sampled, false, has_sample)
}

enum InventoryCodecRequest {
    Encode(u64, u64, InventoryRequest),
    Decode(Vec<u8>),
}

enum InventoryCodecReply {
    Encoded(Vec<u8>),
    Decoded(u64, u64, InventoryReply, Vec<u8>),
}

struct InventoryLane {
    decoder_send: std::sync::mpsc::SyncSender<InventoryCodecRequest>,
    decoder_receive: std::sync::mpsc::Receiver<io::Result<InventoryCodecReply>>,
    encoding: bool,
    decoding: bool,
    decoded_payload: Option<Vec<u8>>,
    metric: Option<memcordon_core::Metric>,
    child: Child,
    stream: UnixStream,
    run: u64,
    sequence: u64,
    outgoing: Vec<u8>,
    sent: usize,
    incoming: Vec<u8>,
    pending: bool,
    stopping: bool,
}

impl InventoryLane {
    fn start(image: &Path, run: u64, deadline: Instant) -> io::Result<Self> {
        let (decoder_send, decoder_requests) =
            std::sync::mpsc::sync_channel::<InventoryCodecRequest>(1);
        let (decoder_results, decoder_receive) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("memcordon-inspector-decoder".into())
            .spawn(move || {
                while let Ok(request) = decoder_requests.recv() {
                    let result = (|| -> io::Result<_> {
                        match request {
                            InventoryCodecRequest::Encode(run, sequence, request) => {
                                Ok(InventoryCodecReply::Encoded(inventory_frame(&(
                                    run, sequence, request,
                                ))?))
                            }
                            InventoryCodecRequest::Decode(bytes) => {
                                let (run, sequence, mut reply): (u64, u64, InventoryReply) =
                                    serde_json::from_slice(&bytes)?;
                                // Positive emptiness proves zero usage for every metric.
                                // Preencode that answer here so a metric query queued
                                // behind a background inventory cannot outlive the lane.
                                normalize_inventory_sample(&mut reply);
                                let payload = serde_json::to_vec(&reply)?;
                                if payload.len() > INVENTORY_FRAME_LIMIT {
                                    return Err(io::Error::other(
                                        "decoded inventory exceeds bound",
                                    ));
                                }
                                Ok(InventoryCodecReply::Decoded(run, sequence, reply, payload))
                            }
                        }
                    })();
                    if decoder_results.send(result).is_err() {
                        break;
                    }
                }
            })?;
        let (stream, endpoint) = private_pair()?;
        let args = [
            OsString::from("__macos-inspector-v1"),
            endpoint.as_raw_fd().to_string().into(),
            run.to_string().into(),
        ];
        let child = native_spawn(image, &args, endpoint.as_raw_fd(), true, deadline)?;
        drop(endpoint);
        stream.set_nonblocking(true)?;
        let mut lane = Self {
            decoder_send,
            decoder_receive,
            encoding: false,
            decoding: false,
            decoded_payload: None,
            metric: None,
            child,
            stream,
            run,
            sequence: 0,
            outgoing: Vec::new(),
            sent: 0,
            incoming: Vec::new(),
            pending: true,
            stopping: false,
        };
        loop {
            if Instant::now() >= deadline {
                lane.cancel_owned();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "inspector readiness expired",
                ));
            }
            match lane.poll() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(error) => {
                    lane.cancel_owned();
                    return Err(error);
                }
            }
            let mut poll = libc::pollfd {
                fd: lane.stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe {
                libc::poll(&mut poll, 1, 1);
            }
        }
        Ok(lane)
    }

    fn submit(&mut self, request: InventoryRequest) -> io::Result<()> {
        if self.pending || self.stopping {
            return Err(io::Error::other("inspector lane unavailable"));
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("inspector sequence overflow"))?;
        self.metric = request.3;
        self.decoder_send
            .try_send(InventoryCodecRequest::Encode(
                self.run,
                self.sequence,
                request,
            ))
            .map_err(|_| io::Error::other("inspector encoder capacity unavailable"))?;
        self.encoding = true;
        self.sent = 0;
        self.pending = true;
        Ok(())
    }

    fn poll(&mut self) -> io::Result<Option<InventoryReply>> {
        if !self.pending {
            return Ok(None);
        }
        if self.encoding {
            match self.decoder_receive.try_recv() {
                Ok(result) => {
                    self.encoding = false;
                    let InventoryCodecReply::Encoded(bytes) = result? else {
                        return Err(io::Error::other("inspector encoder state mismatch"));
                    };
                    self.outgoing = bytes;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(None),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.encoding = false;
                    return Err(io::Error::other("inspector encoder unavailable"));
                }
            }
        }
        if self.decoding {
            return match self.decoder_receive.try_recv() {
                Ok(result) => {
                    self.decoding = false;
                    let InventoryCodecReply::Decoded(run, sequence, reply, payload) = result?
                    else {
                        return Err(io::Error::other("inspector decoder state mismatch"));
                    };
                    if run != self.run || sequence != self.sequence {
                        return Err(io::Error::other("inspector response binding mismatch"));
                    }
                    self.decoded_payload = Some(payload);
                    self.outgoing.clear();
                    self.pending = false;
                    Ok(Some(reply))
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => Ok(None),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.decoding = false;
                    Err(io::Error::other("inspector decoder unavailable"))
                }
            };
        }
        if self.sent < self.outgoing.len() {
            let end = self.outgoing.len().min(self.sent.saturating_add(65536));
            match self.stream.write(&self.outgoing[self.sent..end]) {
                Ok(0) => return Err(io::Error::other("inspector request channel closed")),
                Ok(written) => self.sent += written,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        let mut bytes = [0_u8; 65536];
        match self.stream.read(&mut bytes) {
            Ok(0) => return Err(io::Error::other("inspector response channel closed")),
            Ok(length) => {
                if self.incoming.len().saturating_add(length) > INVENTORY_FRAME_LIMIT {
                    return Err(io::Error::other("inspector frame exceeds bound"));
                }
                self.incoming.extend_from_slice(&bytes[..length]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
        if self.incoming.len() < std::mem::size_of::<u32>() {
            return Ok(None);
        }
        let header = std::mem::size_of::<u32>();
        let length =
            u32::from_be_bytes(self.incoming[..header].try_into().expect("frame header")) as usize;
        if length > INVENTORY_FRAME_LIMIT - header {
            return Err(io::Error::other("inspector declared frame exceeds bound"));
        }
        if self.incoming.len() < header + length {
            return Ok(None);
        }
        if self.incoming.len() != header + length {
            return Err(io::Error::other("unsolicited inspector response"));
        }
        self.incoming.drain(..header);
        self.decoder_send
            .try_send(InventoryCodecRequest::Decode(std::mem::take(
                &mut self.incoming,
            )))
            .map_err(|_| io::Error::other("inspector decoder capacity unavailable"))?;
        self.decoding = true;
        Ok(None)
    }

    fn retire(&mut self) -> io::Result<bool> {
        if self.pending || self.encoding || self.decoding {
            return Ok(false);
        }
        if !self.stopping {
            self.stream.shutdown(std::net::Shutdown::Both)?;
            self.stopping = true;
        }
        Ok(self.child.try_wait()?.is_some())
    }

    fn cancel_owned(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        // Startup has not authorized any workload. If native helper retirement
        // stalls, this guardian remains its custodian while the frontend returns
        // its independently bounded incomplete-startup result.
        loop {
            let _ = self.child.kill();
            if self.child.try_wait().is_ok_and(|status| status.is_some()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

const INVENTORY_FRAME_LIMIT: usize = 8 * 1024 * 1024;

struct InventoryOutput {
    query: u64,
    payload: Vec<u8>,
    offset: usize,
    frame: Vec<u8>,
    sent: usize,
}

impl InventoryOutput {
    fn from_payload(query: u64, payload: Vec<u8>) -> Self {
        Self {
            query,
            payload,
            offset: 0,
            frame: Vec::new(),
            sent: 0,
        }
    }
    fn new(query: u64, reply: &InventoryReply) -> io::Result<Self> {
        let payload = serde_json::to_vec(reply)?;
        if payload.len() > INVENTORY_FRAME_LIMIT {
            return Err(io::Error::other("guardian inventory payload exceeds bound"));
        }
        Ok(Self {
            query,
            payload,
            offset: 0,
            frame: Vec::new(),
            sent: 0,
        })
    }
    fn poll(&mut self, channel: &mut Channel) -> io::Result<bool> {
        // At most 32 frames and 64 KiB of writes per guardian turn. A blocked
        // frontend cannot delay clock service or native termination.
        let mut budget = 65536_usize;
        for _ in 0..32 {
            if self.frame.is_empty() {
                let end = self.payload.len().min(self.offset.saturating_add(512));
                let bytes = serde_json::to_vec(&Frame {
                    version: 2,
                    run: channel.run,
                    sequence: channel.sent,
                    message: Message::InventoryChunk {
                        query: self.query,
                        bytes: self.payload[self.offset..end].to_vec(),
                        finished: end == self.payload.len(),
                    },
                })?;
                if bytes.len() > FRAME_LIMIT {
                    return Err(io::Error::other("inventory chunk exceeds protocol bound"));
                }
                self.frame.extend_from_slice(
                    &u16::try_from(bytes.len())
                        .expect("bounded frame")
                        .to_be_bytes(),
                );
                self.frame.extend(bytes);
                self.offset = end;
                self.sent = 0;
            }
            let end = self.frame.len().min(self.sent.saturating_add(budget));
            match channel.stream.write(&self.frame[self.sent..end]) {
                Ok(0) => return Err(io::Error::other("guardian inventory peer closed")),
                Ok(count) => {
                    self.sent += count;
                    budget -= count;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
            if self.sent == self.frame.len() {
                channel.sent = channel
                    .sent
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("protocol sequence exhausted"))?;
                self.frame.clear();
                if self.offset == self.payload.len() {
                    return Ok(true);
                }
            }
            if budget == 0 {
                return Ok(false);
            }
        }
        Ok(false)
    }
}

fn inventory_frame(value: &impl serde::Serialize) -> io::Result<Vec<u8>> {
    let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
    if payload.len() > INVENTORY_FRAME_LIMIT - std::mem::size_of::<u32>() {
        return Err(io::Error::other("inspector payload exceeds bound"));
    }
    let mut bytes = Vec::with_capacity(payload.len() + std::mem::size_of::<u32>());
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("bounded payload")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

pub fn inspector_helper(descriptor: RawFd, expected_run: u64) -> i32 {
    if descriptor < 3 || unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
        return 126;
    }
    // SAFETY: validated inherited private descriptor, consumed by this helper exactly once.
    let mut stream = unsafe { UnixStream::from_raw_fd(descriptor) };
    let limit = unsafe { libc::getdtablesize() };
    if !(3..=1_048_576).contains(&limit) {
        return 126;
    }
    for fd in 3..limit {
        if fd != descriptor {
            unsafe {
                libc::close(fd);
            }
        }
    }
    if stream.set_nonblocking(false).is_err() {
        return 126;
    }
    let ready: InventoryReply = (Ok(Vec::new()), InventoryIdentities::new(), None);
    let Ok(ready) = inventory_frame(&(expected_run, 0_u64, ready)) else {
        return 125;
    };
    if stream.write_all(&ready).is_err() {
        return 125;
    }
    let mut sequence = 0_u64;
    loop {
        let mut header = [0_u8; std::mem::size_of::<u32>()];
        match stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return 0,
            Err(_) => return 125,
        }
        let length = u32::from_be_bytes(header) as usize;
        if length > INVENTORY_FRAME_LIMIT - header.len() {
            return 126;
        }
        let mut payload = vec![0_u8; length];
        if stream.read_exact(&mut payload).is_err() {
            return 125;
        }
        let Ok((run, next, (root, mut known, signal, metric))) =
            serde_json::from_slice::<(u64, u64, InventoryRequest)>(&payload)
        else {
            return 126;
        };
        if run != expected_run
            || sequence.checked_add(1) != Some(next)
            || root <= 0
            || known.len() > 32768
            || known.iter().any(|identity| identity.pid <= 0)
        {
            return 126;
        }
        if signal.is_some_and(|signal| {
            ![
                libc::SIGKILL,
                libc::SIGTERM,
                libc::SIGINT,
                libc::SIGHUP,
                libc::SIGQUIT,
            ]
            .contains(&signal)
        }) {
            return 126;
        }
        sequence = next;
        let result = crate::macos_watchdog::guardian_inventory(root, &mut known, signal);
        let sample = metric.map(|metric| {
            result
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|snapshots| crate::macos_watchdog::sample_native(snapshots, metric))
        });
        let Ok(response) = inventory_frame(&(run, sequence, (result, known, sample))) else {
            return 125;
        };
        if stream.write_all(&response).is_err() {
            return 125;
        }
    }
}

fn guardian_main(
    mut control: Channel,
    command: &[OsString],
    envelope: crate::macos_envelope::Envelope,
) -> io::Result<i32> {
    let queue = unsafe { libc::kqueue() };
    if queue < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: kqueue returned a new descriptor exclusively owned by this event loop.
    let queue = unsafe { std::os::fd::OwnedFd::from_raw_fd(queue) };
    let event = libc::kevent {
        ident: control.stream.as_raw_fd() as usize,
        filter: libc::EVFILT_READ,
        flags: libc::EV_ADD | libc::EV_ENABLE,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let immediate = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe {
        libc::kevent(
            queue.as_raw_fd(),
            &event,
            1,
            std::ptr::null_mut(),
            0,
            &immediate,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let initial = Instant::now() + STARTUP;
    control.send(Message::Hello, initial)?;
    let configuration = control.receive(initial)?;
    #[cfg(feature = "test-support")]
    let hold_spawn = matches!(
        configuration,
        Some(Message::HoldSpawn | Message::HoldSpawnReleaseAfterCancel)
    );
    #[cfg(feature = "test-support")]
    let release_after_cancel = configuration == Some(Message::HoldSpawnReleaseAfterCancel);
    #[cfg(feature = "test-support")]
    let configuration = if hold_spawn {
        control.receive(initial)?
    } else {
        configuration
    };
    let (startup, work, grace, image, boot_identity) = match configuration {
        Some(Message::Configure {
            image,
            boot_identity,
            startup,
            work,
            grace,
        }) => (
            startup,
            work,
            grace,
            std::path::PathBuf::from(OsString::from_vec(image)),
            boot_identity,
        ),
        _ => {
            return Err(io::Error::other(
                "guardian requires immutable configuration",
            ));
        }
    };
    let now = crate::macos_deadline::continuous_nanos()?;
    if boot_identity != crate::macos_deadline::boot_identity()? {
        return Err(io::Error::other(
            "guardian continuous clock boot binding mismatch",
        ));
    }
    if now >= startup || work.is_some_and(|expiry| now >= expiry) {
        return Ok(126);
    }
    // The dedicated guardian is the sole reaper; the launcher restores the caller's
    // inherited SIGCHLD disposition before executing target code.
    if unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) } == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    let inspector_deadline = Instant::now()
        .checked_add(Duration::from_nanos(startup.saturating_sub(now)))
        .ok_or_else(|| io::Error::other("inspector startup deadline range"))?;
    let mut normal = InventoryLane::start(&image, control.run, inspector_deadline)?;
    let emergency = match InventoryLane::start(&image, control.run, inspector_deadline) {
        Ok(lane) => lane,
        Err(error) => {
            normal.cancel_owned();
            return Err(error);
        }
    };
    let mut inventory_lanes = [normal, emergency];
    control.send(Message::Ready, inspector_deadline)?;
    // Validate every reserve before creation; no overflow may authorize an unbounded fallback.
    work.unwrap_or(startup)
        .checked_add(grace)
        .and_then(|at| at.checked_add(4_000_000_000))
        .ok_or_else(|| io::Error::other("guardian retirement deadline overflow"))?;
    let (parent, original_endpoint) = private_pair()?;
    let endpoint = UnixStream::from(crate::macos_envelope::duplicate(
        original_endpoint.as_raw_fd(),
        envelope.private_floor()?,
    )?);
    drop(original_endpoint);
    let run = control.run;
    let command = command.to_vec();
    let (spawn_send, spawn_receive) = std::sync::mpsc::sync_channel(1);
    #[cfg(feature = "test-support")]
    let (held_send, held_receive) = std::sync::mpsc::sync_channel(1);
    #[cfg(feature = "test-support")]
    let (resume_send, resume_receive) = std::sync::mpsc::sync_channel(1);
    #[cfg(feature = "test-support")]
    let mut resume_send = Some(resume_send);
    // One reserved creation operation. Its publication remains owned even after startup expiry.
    std::thread::Builder::new()
        .name("memcordon-guardian-spawn".into())
        .spawn(move || {
            let result = (|| {
                let mut args = vec![
                    OsString::from("__macos-launcher"),
                    endpoint.as_raw_fd().to_string().into(),
                    run.to_string().into(),
                    OsString::from("--"),
                ];
                args.extend(command);
                let source = unsafe { libc::fcntl(endpoint.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
                if source < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: uniquely owns the just-created duplicate through the native call.
                let source = unsafe { std::os::fd::OwnedFd::from_raw_fd(source) };
                if crate::macos_deadline::continuous_nanos()? >= startup {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "spawn admission expired",
                    ));
                }
                let mut channel = Channel::new(parent, run)?;
                let settings = envelope.settings.clone();
                let child = native_spawn_owned(
                    &image,
                    &args,
                    endpoint.as_raw_fd(),
                    false,
                    source,
                    std::env::vars_os().collect(),
                    SpawnEnvelope {
                        context: Some(envelope),
                        auxiliary: None,
                        target: true,
                    },
                )?;
                #[cfg(feature = "test-support")]
                if hold_spawn {
                    let _ = held_send.send(child.pid);
                    let _ = resume_receive.recv();
                }
                // Target inherited the caller dispositions while gated. Only the guardian
                // now selects single-owner reaping and orphan-group survival behavior.
                unsafe {
                    libc::signal(libc::SIGCHLD, libc::SIG_DFL);
                    libc::signal(libc::SIGHUP, libc::SIG_IGN);
                }
                // Publication is mandatory even when the setup lease expired during
                // creation. The event loop adopts this child exclusively for cancellation.
                let remaining = crate::macos_deadline::continuous_nanos()
                    .map(|now| startup.saturating_sub(now))
                    .unwrap_or(0);
                #[cfg(feature = "test-support")]
                let remaining = if release_after_cancel {
                    u64::try_from(Duration::from_secs(1).as_nanos()).expect("bounded mutation wait")
                } else {
                    remaining
                };
                let _ = channel.send(
                    Message::RestoreSignal { settings },
                    Instant::now() + Duration::from_nanos(remaining),
                );
                #[cfg(feature = "test-support")]
                if release_after_cancel {
                    // Deliberately restore the forbidden late authorization so the
                    // real gated-child marker oracle must reject this mutation.
                    let deadline = Instant::now() + Duration::from_secs(1);
                    channel.expect(Message::Ready, deadline)?;
                    channel.send(Message::Release, deadline)?;
                    let _ = channel.receive(deadline);
                }
                Ok((child, channel))
            })();
            let _ = spawn_send.send(result);
        })?;
    let mut target: Option<Child> = None;
    let mut launcher: Option<Channel> = None;
    let mut witness = None;
    let mut prepared = false;
    let mut released = false;
    let mut confirmed = false;
    let mut connected = true;
    let mut terminal: Option<u64> = None;
    let mut force_at = None;
    let mut force_requested = None;
    let mut force_receipt_sent = false;
    let mut queued_signal = None;
    let mut group_signal_error: Option<String> = None;
    let mut known = std::collections::HashSet::new();
    let mut inspection: Option<()> = None;
    let mut frontend_inspection: Option<(u64, Option<memcordon_core::Metric>)> = None;
    let mut inventory_output: Option<InventoryOutput> = None;
    let mut empty = false;
    let mut last_inspection = 0;
    let mut last_control = now;
    #[cfg(feature = "test-support")]
    let mut clock_advance = 0_u64;
    #[cfg(feature = "test-support")]
    let mut timer_disabled = false;
    let result = (|| {
        loop {
            let now = crate::macos_deadline::continuous_nanos()?;
            #[cfg(feature = "test-support")]
            let now = now
                .checked_add(clock_advance)
                .ok_or_else(|| io::Error::other("fixture clock overflow"))?;
            #[cfg(feature = "test-support")]
            {
                if let Ok(pid) = held_receive.try_recv() {
                    control.send(
                        Message::SpawnHeld { pid },
                        Instant::now() + Duration::from_millis(20),
                    )?;
                }
                if !connected {
                    if let Some(resume) = resume_send.take() {
                        let _ = resume.send(());
                    }
                }
            }
            if terminal.is_none() && released && now.saturating_sub(last_control) >= 2_000_000_000 {
                terminal = Some(now);
                force_at = Some(now);
            }
            let expiry = if released { work } else { Some(startup) };
            #[cfg(feature = "test-support")]
            let expiry = if timer_disabled { None } else { expiry };
            if terminal.is_none() && expiry.is_some_and(|at| now >= at) {
                let anchor = expiry.expect("expired boundary");
                terminal = Some(anchor);
                force_at = Some(
                    anchor
                        .checked_add(if released { grace } else { 0 })
                        .ok_or_else(|| io::Error::other("force deadline overflow"))?,
                );
                if released && grace != 0 {
                    if let Some(child) = &target {
                        unsafe { libc::kill(-child.pid, libc::SIGTERM) };
                    }
                }
            }
            if target.is_none() {
                match spawn_receive.try_recv() {
                    Ok(Ok((child, channel))) => {
                        let pid = child.pid;
                        target = Some(child);
                        launcher = Some(channel);
                        // Adoption must precede every fallible post-spawn operation.
                        // Expired creations need cancellation, never an exec witness.
                        if terminal.is_none() {
                            witness = Some(ExecWitness::new(pid)?);
                        }
                        // The spawn operation dropped every owned caller descriptor on publication.
                    }
                    Ok(Err(error)) => {
                        if connected {
                            let _ = control.send(
                                Message::Failure {
                                    errno: error.raw_os_error().unwrap_or(libc::EIO),
                                },
                                Instant::now() + Duration::from_millis(20),
                            );
                        }
                        return Ok(126);
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => return Ok(126),
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
            }
            if terminal.is_some() && force_at.is_some_and(|at| now >= at) {
                if let Some(child) = &target {
                    force_requested.get_or_insert(crate::macos_deadline::continuous_nanos()?);
                    if let Err(error) = child.kill() {
                        group_signal_error.get_or_insert_with(|| error.to_string());
                        // A failed group request is not an absence proof. The root
                        // remains owned and receives an independent direct request;
                        // inspector reconciliation must still prove group retirement.
                        unsafe { libc::kill(child.pid, libc::SIGKILL) };
                    }
                }
                launcher.take();
            }
            if let Some(channel) = &mut launcher {
                match channel.receive_available() {
                    Ok(Some(Some(Message::Ready))) if !prepared && terminal.is_none() => {
                        prepared = true;
                        control.send(
                            Message::Prepared {
                                pid: target.as_ref().expect("launcher owned").pid,
                            },
                            Instant::now() + Duration::from_millis(20),
                        )?;
                    }
                    Ok(Some(None)) if released && !confirmed => {
                        if witness
                            .as_ref()
                            .expect("exec witness reserved")
                            .confirm(Instant::now() + Duration::from_millis(20))
                            .is_ok()
                        {
                            confirmed = true;
                            control.send(
                                Message::Released,
                                Instant::now() + Duration::from_millis(20),
                            )?;
                        } else {
                            terminal.get_or_insert(now);
                            force_at.get_or_insert(now);
                        }
                        launcher = None;
                    }
                    Ok(Some(Some(Message::Failure { errno }))) => {
                        let _ = control.send(
                            Message::Failure { errno },
                            Instant::now() + Duration::from_millis(20),
                        );
                        terminal.get_or_insert(now);
                        force_at.get_or_insert(now);
                        launcher = None;
                    }
                    Ok(None) => {}
                    _ => {
                        terminal.get_or_insert(now);
                        force_at.get_or_insert(now);
                        launcher = None;
                    }
                }
            }
            for (index, lane) in inventory_lanes.iter_mut().enumerate() {
                if !lane.pending {
                    continue;
                }
                match lane.poll() {
                    Ok(Some((mut result, identities, sample))) => {
                        if index == 1 {
                            if result.as_ref().is_ok_and(|members| members.is_empty()) {
                                group_signal_error = None;
                            } else if let (Err(error), Some(signal_error)) =
                                (&mut result, &group_signal_error)
                            {
                                *error =
                                    format!("{error}; pinned group signal failed: {signal_error}");
                            }
                        }
                        if frontend_inspection.is_some_and(|(_, metric)| {
                            inventory_answers_query(
                                metric,
                                lane.metric,
                                result.as_ref().is_ok_and(|members| members.is_empty()),
                                sample.is_some(),
                            )
                        }) && (terminal.is_none() || index == 1)
                        {
                            inventory_output = Some(InventoryOutput::from_payload(
                                frontend_inspection.expect("pending inspection").0,
                                lane.decoded_payload
                                    .take()
                                    .expect("completed inventory decoder payload"),
                            ));
                            frontend_inspection = None;
                        }
                        if terminal.is_none() || index == 1 {
                            known = identities;
                        } else {
                            let newly_observed =
                                identities.iter().any(|identity| !known.contains(identity));
                            known.extend(identities);
                            if newly_observed {
                                empty = false;
                            }
                        }
                        lane.pending = false;
                        match result {
                            Ok(snapshots) if terminal.is_none() || index == 1 => {
                                empty = snapshots.is_empty()
                            }
                            Ok(_) => {}
                            Err(_) => {
                                empty = false;
                                terminal.get_or_insert(now);
                                force_at.get_or_insert(now);
                            }
                        }
                    }
                    Err(_) => {
                        empty = false;
                        terminal.get_or_insert(now);
                        force_at.get_or_insert(now);
                        let _ = lane.child.kill();
                        if lane.child.try_wait()?.is_some() {
                            lane.pending = false;
                            lane.stopping = true;
                        }
                    }
                    Ok(None) => {}
                }
            }
            let lane = &mut inventory_lanes[usize::from(terminal.is_some())];
            if let Some(child) = target.as_ref().filter(|_| {
                !lane.pending
                    && !lane.stopping
                    && !empty
                    && (frontend_inspection.is_some()
                        || now.saturating_sub(last_inspection) >= 20_000_000)
            }) {
                let root = child.pid;
                let signal = if force_at.is_some_and(|force| now >= force) {
                    Some(libc::SIGKILL)
                } else {
                    queued_signal.take()
                };
                lane.submit((
                    root,
                    known.clone(),
                    signal,
                    frontend_inspection.and_then(|(_, metric)| metric),
                ))?;
                last_inspection = now;
            }
            let pending = inventory_lanes.iter().any(|lane| lane.pending);
            let mut inspectors_retired = false;
            if empty && !pending {
                inspectors_retired = true;
                for lane in &mut inventory_lanes {
                    inspectors_retired &= lane.retire()?;
                }
            }
            inspection = (pending || (empty && !inspectors_retired)).then_some(());
            if let Some(output) = &mut inventory_output {
                match output.poll(&mut control) {
                    Ok(true) => inventory_output = None,
                    Ok(false) => {}
                    Err(_) => {
                        inventory_output = None;
                        connected = false;
                        terminal.get_or_insert(now);
                        force_at.get_or_insert(now);
                    }
                }
            }
            if connected && inventory_output.is_none() {
                if let Some(at) = force_requested.filter(|_| !force_receipt_sent) {
                    control.send(
                        Message::ForceRequested { at },
                        Instant::now() + Duration::from_millis(20),
                    )?;
                    force_receipt_sent = true;
                }
                match control.receive_available() {
                    Ok(Some(Some(message))) => {
                        last_control = now;
                        let response_deadline = Instant::now() + Duration::from_millis(20);
                        match message {
                            #[cfg(feature = "test-support")]
                            Message::ResumeSpawn => {
                                if let Some(resume) = resume_send.take() {
                                    let _ = resume.send(());
                                }
                            }
                            #[cfg(feature = "test-support")]
                            Message::InterruptClock => {
                                extern "C" fn interrupt(_: libc::c_int) {}
                                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                                action.sa_sigaction = interrupt as *const () as usize;
                                action.sa_flags = 0;
                                unsafe {
                                    libc::sigemptyset(&mut action.sa_mask);
                                }
                                if unsafe {
                                    libc::sigaction(libc::SIGUSR2, &action, std::ptr::null_mut())
                                } != 0
                                {
                                    return Err(io::Error::last_os_error());
                                }
                                control.send(Message::ClockInterruptible, response_deadline)?;
                            }
                            #[cfg(feature = "test-support")]
                            Message::AdvanceClock { nanos } => {
                                clock_advance =
                                    clock_advance.checked_add(nanos).ok_or_else(|| {
                                        io::Error::other("fixture clock advance overflow")
                                    })?;
                            }
                            #[cfg(feature = "test-support")]
                            Message::DisableWorkTimer => timer_disabled = true,
                            Message::InventoryQuery { query, metric } => {
                                if empty {
                                    inventory_output = Some(InventoryOutput::new(
                                        query,
                                        &(Ok(Vec::new()), known.clone(), metric.map(|_| Ok(0))),
                                    )?);
                                } else {
                                    frontend_inspection = Some((query, metric));
                                }
                            }
                            Message::Heartbeat => {}
                            Message::SignalStop { signal, force }
                                if matches!(
                                    signal,
                                    libc::SIGKILL
                                        | libc::SIGTERM
                                        | libc::SIGINT
                                        | libc::SIGHUP
                                        | libc::SIGQUIT
                                ) =>
                            {
                                if terminal.is_none() {
                                    terminal = Some(now);
                                    force_at = Some(work.map_or(force, |expiry| {
                                        force.min(expiry.saturating_add(grace))
                                    }));
                                    queued_signal = Some(signal);
                                    if let Some(child) = &target {
                                        if child.status.is_none()
                                            && unsafe { libc::kill(-child.pid, signal) } != 0
                                            && io::Error::last_os_error().raw_os_error()
                                                != Some(libc::ESRCH)
                                        {
                                            group_signal_error.get_or_insert_with(|| {
                                                io::Error::last_os_error().to_string()
                                            });
                                            unsafe { libc::kill(child.pid, signal) };
                                        }
                                    }
                                }
                            }
                            Message::StopAt { force } => {
                                if terminal.is_none() {
                                    terminal = Some(now);
                                    force_at = Some(work.map_or(force, |expiry| {
                                        force.min(expiry.saturating_add(grace))
                                    }));
                                }
                            }
                            Message::Release
                                if prepared
                                    && !released
                                    && terminal.is_none()
                                    && now < startup
                                    && work.is_none_or(|at| now < at) =>
                            {
                                launcher
                                    .as_mut()
                                    .expect("gated launcher")
                                    .send(Message::Release, response_deadline)?;
                                released = true;
                                control
                                    .send(Message::ReleaseIssued { at: now }, response_deadline)?;
                            }
                            Message::Observe => {
                                let child = target
                                    .as_ref()
                                    .ok_or_else(|| io::Error::other("target not prepared"))?;
                                control.send(
                                    Message::Status {
                                        raw: child.observe()?.map(ExitStatus::into_raw),
                                        reaped: child.status.is_some(),
                                    },
                                    response_deadline,
                                )?;
                            }
                            Message::Reap => {
                                let child = target
                                    .as_mut()
                                    .ok_or_else(|| io::Error::other("target not prepared"))?;
                                let status = if empty && inspection.is_none() {
                                    child.try_wait()?
                                } else {
                                    None
                                };
                                control.send(
                                    Message::Status {
                                        raw: status.map(ExitStatus::into_raw),
                                        reaped: child.status.is_some(),
                                    },
                                    response_deadline,
                                )?;
                            }
                            Message::Stop => {
                                terminal.get_or_insert(now);
                                force_at.get_or_insert(now);
                            }
                            Message::Disarm
                                if empty
                                    && target
                                        .as_ref()
                                        .is_some_and(|child| child.status.is_some())
                                    && inspection.is_none() =>
                            {
                                control.send(Message::Retired, response_deadline)?;
                                return Ok(0);
                            }
                            #[cfg(feature = "test-support")]
                            Message::StallInspectors { both } => {
                                for (index, lane) in inventory_lanes.iter_mut().enumerate() {
                                    if index == 0 || both {
                                        if unsafe { libc::kill(lane.child.pid, libc::SIGSTOP) } != 0
                                        {
                                            return Err(io::Error::last_os_error());
                                        }
                                        if !lane.pending {
                                            lane.submit((
                                                target.as_ref().expect("fixture target").pid,
                                                known.clone(),
                                                None,
                                                None,
                                            ))?;
                                        }
                                    }
                                }
                                control.send(
                                    Message::InspectorsStalled {
                                        normal: inventory_lanes[0].child.id(),
                                        emergency: inventory_lanes[1].child.id(),
                                    },
                                    response_deadline,
                                )?;
                            }
                            #[cfg(feature = "test-support")]
                            Message::Snapshot { pid } => {
                                control.send(
                                    Message::Observed {
                                        pid,
                                        observed: known.iter().any(|identity| identity.pid == pid),
                                    },
                                    response_deadline,
                                )?;
                            }
                            _ => {
                                terminal.get_or_insert(now);
                                force_at.get_or_insert(now);
                            }
                        }
                    }
                    Ok(None) => {}
                    _ => {
                        connected = false;
                        terminal.get_or_insert(now);
                        force_at.get_or_insert(now);
                    }
                }
            }
            if !connected && empty && inspection.is_none() {
                if let Some(child) = &mut target {
                    if child.try_wait()?.is_some() {
                        return Ok(0);
                    }
                }
            }
            let mut ready = std::mem::MaybeUninit::<libc::kevent>::uninit();
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 10_000_000,
            };
            // SAFETY: finite native wait services the independently owned clock every turn.
            let result = unsafe {
                libc::kevent(
                    queue.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    ready.as_mut_ptr(),
                    1,
                    &timeout,
                )
            };
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(io::Error::last_os_error());
            }
        }
    })();
    if let Err(error) = &result {
        #[cfg(feature = "test-support")]
        if let Some(resume) = resume_send.take() {
            let _ = resume.send(());
        }
        if inventory_output.is_none() {
            let _ = control.send(
                Message::FailureDetail {
                    message: error.to_string(),
                },
                Instant::now() + Duration::from_millis(20),
            );
        }
        // An IPC/native error is not permission for the custodian to exit. Keep
        // the actual child and any in-flight creation until retirement can be proved.
        drop(control);
        launcher.take();
        empty = false;
        let mut creation_settled = target.is_some();
        loop {
            if !creation_settled {
                match spawn_receive.try_recv() {
                    Ok(Ok((child, channel))) => {
                        drop(channel);
                        target = Some(child);
                        creation_settled = true;
                    }
                    Ok(Err(_)) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        creation_settled = true;
                        empty = true;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
            }
            if let Some(child) = &mut target {
                let _ = child.kill();
            }
            for (index, lane) in inventory_lanes.iter_mut().enumerate() {
                if !lane.pending {
                    continue;
                }
                match lane.poll() {
                    Ok(Some((observed, identities, _))) => {
                        if index == 1 {
                            known = identities;
                            empty = observed.is_ok_and(|members| members.is_empty());
                        } else {
                            let newly_observed =
                                identities.iter().any(|identity| !known.contains(identity));
                            known.extend(identities);
                            if newly_observed {
                                empty = false;
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(_) => {
                        let _ = lane.child.kill();
                        if lane.child.try_wait().is_ok_and(|status| status.is_some()) {
                            lane.pending = false;
                            lane.stopping = true;
                        }
                        empty = false;
                    }
                }
            }
            if let Some(child) = &target {
                let emergency = &mut inventory_lanes[1];
                if !empty && !emergency.pending && !emergency.stopping {
                    let _ = emergency.submit((child.pid, known.clone(), Some(libc::SIGKILL), None));
                }
            }
            if empty && !inventory_lanes.iter().any(|lane| lane.pending) {
                let retired = inventory_lanes
                    .iter_mut()
                    .all(|lane| lane.retire().unwrap_or(false));
                if retired
                    && (target.is_none()
                        || target.as_mut().is_some_and(|child| {
                            child.try_wait().is_ok_and(|status| status.is_some())
                        }))
                {
                    return Ok(126);
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    result
}

/// Dispatch only after CLI has checked the hidden native arguments.
pub fn helper(guardian: bool, descriptor: RawFd, run: u64, command: &[OsString]) -> i32 {
    if guardian {
        return 126;
    }
    helper_inner(descriptor, run, command, None)
}

pub fn enveloped_helper(
    descriptor: RawFd,
    run: u64,
    envelope_descriptor: RawFd,
    command: &[OsString],
) -> i32 {
    if envelope_descriptor < 3 || envelope_descriptor == descriptor {
        return 126;
    }
    if unsafe { libc::fcntl(envelope_descriptor, libc::F_GETFD) } < 0 {
        return 126;
    }
    let socket = unsafe { std::os::unix::net::UnixDatagram::from_raw_fd(envelope_descriptor) };
    let Ok(envelope) = crate::macos_envelope::Envelope::receive(
        &socket,
        run,
        descriptor.max(envelope_descriptor).saturating_add(1),
    ) else {
        return 126;
    };
    drop(socket);
    helper_inner(descriptor, run, command, Some(envelope))
}

fn helper_inner(
    descriptor: RawFd,
    run: u64,
    command: &[OsString],
    envelope: Option<crate::macos_envelope::Envelope>,
) -> i32 {
    // SAFETY: validates descriptor before taking unique ownership.
    if descriptor < 3 || unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
        return 126;
    }
    // SAFETY: hidden invocation transfers this inherited socket once.
    let stream = unsafe { UnixStream::from_raw_fd(descriptor) };
    // SAFETY: private control must not survive target exec.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return 126;
    }
    let Ok(mut channel) = Channel::new(stream, run) else {
        return 126;
    };
    if let Some(envelope) = envelope {
        return guardian_main(channel, command, envelope).unwrap_or(126);
    }
    let deadline = Instant::now() + STARTUP;
    let Ok(Some(Message::RestoreSignal { settings })) = channel.receive(deadline) else {
        return 126;
    };
    if settings.restore().is_err() {
        return 126;
    }
    if channel.send(Message::Ready, deadline).is_err()
        || channel.expect(Message::Release, deadline).is_err()
    {
        return 126;
    }
    let Some((program, arguments)) = command.split_first() else {
        return 126;
    };
    let error = exec_native(program, arguments);
    let _ = channel.send(
        Message::Failure {
            errno: error.raw_os_error().unwrap_or(libc::EIO),
        },
        deadline,
    );
    if error.kind() == io::ErrorKind::NotFound {
        127
    } else {
        126
    }
}

#[cfg(feature = "test-support")]
pub fn startup_fault(
    command: &CommandSpec,
    image: &Path,
    fault: LaunchFault,
) -> Result<memcordon_core::NativeStartupDiagnosticV1, String> {
    let deadline = Instant::now() + Duration::from_secs(1);
    match launch_inner(
        command,
        image,
        deadline,
        deadline + Duration::from_secs(1),
        Some(fault),
    ) {
        Err(error) => Ok(error.diagnostic),
        Ok(mut launch) => {
            let _ = launch.child.kill();
            drop(launch.guardian);
            let _ = launch.child.retire(Instant::now() + Duration::from_secs(1));
            Err("injected startup fault unexpectedly released the target".into())
        }
    }
}

#[cfg(feature = "test-support")]
pub fn disarm_timeout(image: &Path) -> Result<(), String> {
    let command = CommandSpec::new(image.as_os_str()).args(["__execution-probe"]);
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut launch =
        launch(&command, image, deadline, deadline).map_err(|error| error.error.to_string())?;
    launch
        .child
        .retire(Instant::now() + Duration::from_secs(1))
        .map_err(|error| error.to_string())?;
    let pid = launch.guardian.child.pid;
    let slot = launch.guardian.child.slot;
    // SAFETY: fixture owns the live guardian and pins it through its runtime slot.
    if unsafe { libc::kill(pid, libc::SIGSTOP) } != 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let started = Instant::now();
    let result = launch.guardian.disarm(started + Duration::from_millis(20));
    let elapsed = started.elapsed();
    // SAFETY: resume the deliberately stopped, still-unreaped fixture guardian.
    unsafe { libc::kill(pid, libc::SIGCONT) };
    let deadline = Instant::now() + Duration::from_secs(1);
    while CHILDREN[slot].load(Ordering::Acquire).checked_abs() == Some(pid)
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    if result.is_ok() || elapsed > Duration::from_millis(250) {
        return Err("disarm timeout fell through to blocking destruction".into());
    }
    if CHILDREN[slot].load(Ordering::Acquire).checked_abs() == Some(pid) {
        return Err("runtime did not discharge abandoned guardian reaping".into());
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub fn rejects_protocol(bytes: &[u8]) -> bool {
    let (left, mut right) = private_pair().expect("fixture private pair");
    let mut channel = Channel::new(left, 7).expect("fixture channel");
    right.write_all(bytes).expect("bounded fixture write");
    drop(right);
    channel
        .expect(Message::Ready, Instant::now() + Duration::from_millis(50))
        .is_err()
}

#[cfg(feature = "test-support")]
pub fn inspector_stall(image: &Path) -> Result<(), String> {
    process_inspector_stall(image)?;
    use crate::macos_watchdog::{
        InspectionAdmission, inspect_until_admitted, inspect_with_admission,
    };

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut launch = launch(
        &CommandSpec::new(image).args(["__execution-probe"]),
        image,
        deadline,
        deadline,
    )
    .map_err(|error| error.error.to_string())?;
    let (entered_send, entered) = std::sync::mpsc::sync_channel(1);
    let (release, blocked) = std::sync::mpsc::sync_channel(1);
    let (done_send, done) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = crate::macos_watchdog::inspect_until(
            Instant::now() + Duration::from_millis(100),
            move || {
                entered_send.send(()).map_err(|error| error.to_string())?;
                blocked.recv().map_err(|error| error.to_string())?;
                Ok(())
            },
        );
        let _ = done_send.send(result);
    });
    entered
        .recv_timeout(Duration::from_secs(1))
        .map_err(|error| error.to_string())?;
    if crate::macos_watchdog::inspection_obligations() == 0 {
        return Err("stalled native inspection lost its runtime obligation".into());
    }
    let queued_executed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let queued_operation = queued_executed.clone();
    let result = (|| {
        let started = Instant::now();
        let expired: Result<(), String> = crate::macos_watchdog::inspect_until(started, || {
            panic!("expired monitoring inspection must not execute")
        });
        if !expired.is_err_and(|error| error.contains("deadline expired")) {
            return Err("expired monitoring inspection was admitted".into());
        }
        let mut full = None;
        let queued = inspect_until_admitted(
            // Admission is a readiness precondition, using the same bounded
            // budget as the worker-entry handshake above.
            Instant::now() + Duration::from_secs(1),
            move || {
                queued_operation.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
            || {
                // Successful admission proves the slot is occupied. Check capacity
                // before waiting for this queued request's deadline, with a fresh budget.
                full = Some(crate::macos_watchdog::inspect_until(
                    Instant::now() + Duration::from_secs(1),
                    || Ok(()),
                ));
            },
        );
        let Some(full) = full else {
            return Err(format!("queued inspection was not admitted: {queued:?}"));
        };
        if !queued
            .as_ref()
            .is_err_and(|error| error.contains("deadline expired"))
        {
            return Err(format!("queued inspection did not time out: {queued:?}"));
        }
        if !full.as_ref().is_err_and(|error| error.contains("busy")) {
            return Err(format!(
                "occupied inspector did not reject capacity: {full:?}"
            ));
        }
        let stalled = done
            .recv_timeout(Duration::from_secs(1))
            .map_err(|error| format!("stalled inspection caller did not return: {error}"))?;
        if !stalled
            .as_ref()
            .is_err_and(|error| error.contains("deadline expired"))
        {
            return Err(format!(
                "stalled inspection caller did not time out: {stalled:?}"
            ));
        }
        let emergency: Result<(), String> = inspect_with_admission(
            Instant::now() + Duration::from_millis(20),
            InspectionAdmission::Cleanup,
            || Ok(()),
        );
        if emergency.is_err() {
            return Err("emergency inspection was blocked by the stalled normal lane".into());
        }
        launch
            .child
            .retire(Instant::now() + Duration::from_millis(500))
            .map_err(|error| error.to_string())?;
        launch
            .guardian
            .disarm(Instant::now() + Duration::from_millis(500))
            .map_err(|error| error.to_string())?;
        Ok(())
    })();
    let release_worker = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        let _ = release.send(());
    });
    // Both normal slots remain occupied; the independent cleanup lane still works.
    let recovered = inspect_with_admission(
        Instant::now() + Duration::from_secs(1),
        InspectionAdmission::Cleanup,
        || Ok(()),
    );
    release_worker
        .join()
        .map_err(|_| "inspector release fixture panicked".to_owned())?;
    recovered?;
    if queued_executed.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("expired queued inspection executed after worker release".into());
    }
    let native_error = inspect_with_admission(
        Instant::now() + Duration::from_secs(1),
        InspectionAdmission::Cleanup,
        || Err::<(), _>("fixture native inspection failure".into()),
    );
    if native_error != Err("fixture native inspection failure".into()) {
        return Err("cleanup admission did not preserve native inspection failure".into());
    }
    let settled_by = Instant::now() + Duration::from_secs(1);
    while crate::macos_watchdog::inspection_obligations() != 0 {
        if Instant::now() >= settled_by {
            return Err("completed or expired inspection retained an obligation".into());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    result
}

#[cfg(feature = "test-support")]
fn process_inspector_stall(image: &Path) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut normal =
        InventoryLane::start(image, 73, deadline).map_err(|error| error.to_string())?;
    let mut emergency = match InventoryLane::start(image, 73, deadline) {
        Ok(lane) => lane,
        Err(error) => {
            normal.cancel_owned();
            return Err(error.to_string());
        }
    };
    let result = (|| -> Result<(), String> {
        // Deliberately freeze the process containing the normal native calls.
        // Only the independent emergency process can complete the next request.
        if unsafe { libc::kill(normal.child.pid, libc::SIGSTOP) } != 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let root = i32::try_from(std::process::id()).map_err(|error| error.to_string())?;
        normal
            .submit((root, InventoryIdentities::new(), None, None))
            .map_err(|error| error.to_string())?;
        emergency
            .submit((root, InventoryIdentities::new(), None, None))
            .map_err(|error| error.to_string())?;
        loop {
            if normal.poll().map_err(|error| error.to_string())?.is_some() {
                return Err("stopped normal inspector unexpectedly replied".into());
            }
            if emergency
                .poll()
                .map_err(|error| error.to_string())?
                .is_some()
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("emergency process was blocked by the stopped normal process".into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    })();
    normal.cancel_owned();
    emergency.cancel_owned();
    result
}

/// Disposable fixture frontend. Its caller kills this process after the atomic
/// identity marker is published; the stopped sibling guardian owns the lease.
#[cfg(feature = "test-support")]
pub fn guardian_inspector_wrapper(
    image: &Path,
    fixture: &Path,
    directory: &Path,
    both: bool,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let work_deadline = crate::macos_deadline::continuous_nanos()
        .and_then(|now| crate::macos_deadline::add(now, Duration::from_secs(1)))
        .map_err(|error| error.to_string())?;
    let mut launch = launch_with_deadline(
        &CommandSpec::new(fixture).args(["hold", "--duration", "20s"]),
        image,
        deadline,
        deadline,
        Some(work_deadline),
        Duration::ZERO,
    )
    .map_err(|error| error.error.to_string())?;
    crate::test_support::ProcessIdentity::for_pid(launch.child.id())
        .and_then(|identity| identity.publish_to(&directory.join("target")))
        .map_err(|error| error.to_string())?;
    let mut channel = launch
        .guardian
        .channel
        .as_mut()
        .expect("guardian channel")
        .lock()
        .map_err(|_| "guardian channel poisoned")?;
    channel
        .send(Message::StallInspectors { both }, deadline)
        .map_err(|error| error.to_string())?;
    let Some(Message::InspectorsStalled { normal, emergency }) = channel
        .receive(deadline)
        .map_err(|error| error.to_string())?
    else {
        return Err("guardian inspector stall acknowledgment missing".into());
    };
    for (name, pid) in [
        ("normal", normal),
        ("emergency", emergency),
        ("guardian", launch.guardian.child.id()),
    ] {
        crate::test_support::ProcessIdentity::for_pid(pid)
            .and_then(|identity| identity.publish_to(&directory.join(name)))
            .map_err(|error| error.to_string())?;
    }
    loop {
        std::thread::park();
    }
}

#[cfg(feature = "test-support")]
pub fn custody_wrapper(
    image: &Path,
    fixture: &Path,
    pid_file: &Path,
    marker: &Path,
) -> Result<(), String> {
    let exit_gate = marker.with_extension("root-exit-gate");
    let group_gate = marker.with_extension("group-gate");
    let command = CommandSpec::new(fixture).args([
        OsString::from("spawn-background"),
        OsString::from("--child-duration"),
        OsString::from("20s"),
        OsString::from("--pid-file"),
        pid_file.as_os_str().to_owned(),
        OsString::from("--exit-gate"),
        exit_gate.as_os_str().to_owned(),
        OsString::from("--child-group-gate"),
        group_gate.as_os_str().to_owned(),
    ]);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut launch =
        launch(&command, image, deadline, deadline).map_err(|error| error.error.to_string())?;
    while !pid_file.exists() {
        if Instant::now() >= deadline {
            return Err("descendant ready marker missing".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let record = std::fs::read_to_string(pid_file).map_err(|error| error.to_string())?;
    let pid: i32 = record
        .split_whitespace()
        .next()
        .ok_or("missing descendant pid")?
        .parse()
        .map_err(|error: std::num::ParseIntError| error.to_string())?;
    let shared_channel = launch
        .guardian
        .channel
        .as_mut()
        .expect("owned guardian lease");
    let mut channel = shared_channel
        .lock()
        .map_err(|_| "guardian channel poisoned")?;
    channel
        .send(Message::Snapshot { pid: i32::MAX }, deadline)
        .map_err(|error| error.to_string())?;
    channel
        .expect(
            Message::Observed {
                pid: i32::MAX,
                observed: false,
            },
            deadline,
        )
        .map_err(|error| error.to_string())?;
    channel
        .send(Message::Snapshot { pid }, deadline)
        .map_err(|error| error.to_string())?;
    loop {
        match channel
            .receive(deadline)
            .map_err(|error| error.to_string())?
        {
            Some(Message::Observed {
                pid: observed_pid,
                observed: true,
            }) if observed_pid == pid => break,
            Some(Message::Observed {
                pid: observed_pid,
                observed: false,
            }) if observed_pid == pid && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
                channel
                    .send(Message::Snapshot { pid }, deadline)
                    .map_err(|error| error.to_string())?;
            }
            other => {
                return Err(format!(
                    "unexpected guardian snapshot acknowledgment: {other:?}"
                ));
            }
        }
    }
    std::fs::write(&group_gate, b"change\n").map_err(|error| error.to_string())?;
    while !group_gate.with_extension("changed").exists() {
        if Instant::now() >= deadline {
            return Err("observed descendant did not change group".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    channel
        .send(Message::Snapshot { pid }, deadline)
        .map_err(|error| error.to_string())?;
    channel
        .expect(
            Message::Observed {
                pid,
                observed: true,
            },
            deadline,
        )
        .map_err(|error| error.to_string())?;
    // SAFETY: owned unreaped guardian identity remains pinned while deliberately stopped.
    if unsafe { libc::kill(launch.guardian.child.pid, libc::SIGSTOP) } != 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    std::fs::write(exit_gate, b"exit\n").map_err(|error| error.to_string())?;
    // The stopped guardian owns the root. Observe its zombie state without sending a
    // reap request: custody must remain pinned until the descendant is reconciled.
    while !crate::macos_watchdog::fixture_root_exited(launch.child.pid)
        .map_err(|error| error.to_string())?
    {
        if Instant::now() >= deadline {
            return Err("target root did not exit while its guardian was stopped".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    crate::test_support::ProcessIdentity::for_pid(launch.guardian.child.id())
        .and_then(|identity| identity.publish_to(marker))
        .map_err(|error| error.to_string())?;
    loop {
        std::thread::park();
    }
}

#[cfg(feature = "test-support")]
pub fn repeated_stop(image: &Path, fixture: &Path, marker: &Path) -> Result<(), String> {
    let end = Instant::now() + Duration::from_secs(4);
    let command = CommandSpec::new(fixture).args([
        OsString::from("macos-ignore-term"),
        marker.as_os_str().to_owned(),
    ]);
    let mut attempt = launch(&command, image, end, end).map_err(|error| error.error.to_string())?;
    while !marker.exists() {
        if Instant::now() >= end {
            return Err("grace fixture readiness missing".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let first = Instant::now();
    attempt
        .guardian
        .signal_stop(libc::SIGTERM, Duration::from_millis(200))
        .map_err(|error| error.to_string())?;
    let shared = attempt
        .guardian
        .channel
        .as_ref()
        .expect("live guardian")
        .clone();
    let mut observed = None;
    for _ in 0..25 {
        let force = crate::macos_deadline::add(
            crate::macos_deadline::continuous_nanos().map_err(|error| error.to_string())?,
            Duration::from_secs(5),
        )
        .map_err(|error| error.to_string())?;
        shared
            .lock()
            .map_err(|_| "guardian control poisoned")?
            .send(Message::StopAt { force }, end)
            .map_err(|error| error.to_string())?;
        if observed.is_none()
            && crate::macos_watchdog::fixture_root_exited(attempt.child.pid)
                .map_err(|error| error.to_string())?
        {
            observed = Some(first.elapsed());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let timely = observed.is_some_and(|elapsed| elapsed < Duration::from_millis(400));
    if !timely {
        // Separate bounded teardown must not become a production success proof.
        unsafe {
            libc::kill(attempt.child.pid, libc::SIGKILL);
        }
    }
    drop(shared);
    attempt
        .child
        .retire(end)
        .map_err(|error| error.to_string())?;
    attempt
        .guardian
        .disarm(end)
        .map_err(|error| error.to_string())?;
    if !timely {
        return Err("repeated stop events renewed the first force deadline".into());
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub fn running_guardian_loss(image: &Path, fixture: &Path) -> Result<(), String> {
    RUNNING_GUARDIAN_LOSS.set(Some(0));
    let started = Instant::now();
    let result = crate::run(
        memcordon_core::Policy::unbounded()
            .with_deadline(STARTUP)
            .map_err(|error| error.to_string())?,
        &CommandSpec::new(fixture).args(["spin"]),
        image,
    );
    let pid = RUNNING_GUARDIAN_LOSS
        .replace(None)
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            format!(
                "running guardian loss hook was not reached: {:?}",
                RUNNING_GUARDIAN_LOSS_FAILURE.take()
            )
        })?;
    let prompt = started.elapsed() < STARTUP + Duration::from_secs(4)
        && RUNNING_GUARDIAN_LOSS_AT
            .replace(None)
            .is_some_and(|at| at.elapsed() < Duration::from_secs(4));
    // Separate fixture teardown: this sole spin target cannot voluntarily exit.
    // Cleanup here is never credited to the production retirement evidence.
    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0
        && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let teardown = Instant::now() + Duration::from_secs(1);
    while !crate::macos_watchdog::fixture_root_exited(pid).map_err(|error| error.to_string())? {
        if Instant::now() >= teardown {
            return Err("guardian loss fixture teardown expired".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let execution =
        result.map_err(|error| format!("running guardian loss returned startup error: {error}"))?;
    if !prompt
        || !matches!(
            execution.outcome,
            memcordon_core::RunOutcome::MonitorFailed { .. }
        )
        || execution.runtime.is_none_or(|runtime| {
            matches!(
                runtime.retirement,
                memcordon_core::RetirementEvidence::Complete { .. }
            )
        })
    {
        return Err("running guardian loss hung or reported clean retirement".into());
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub fn submillisecond_deadline(image: &Path) -> Result<(), String> {
    let start = Instant::now();
    let deadline = start + Duration::from_nanos(1);
    let result = launch_with_deadline(
        &CommandSpec::new(image).args(["__execution-probe"]),
        image,
        deadline,
        start + Duration::from_secs(1),
        None,
        Duration::ZERO,
    );
    match result {
        Err(error)
            if error.error.kind() == io::ErrorKind::TimedOut
                && error.diagnostic.guardian_pid.is_none()
                && error.diagnostic.launcher_pid.is_none()
                && !error.diagnostic.release_sent
                && start.elapsed() < Duration::from_millis(100) =>
        {
            Ok(())
        }
        _ => Err("sub-millisecond expired admission was renewed or created a helper".into()),
    }
}

#[cfg(feature = "test-support")]
pub fn control_flood(image: &Path, fixture: &Path) -> Result<(), String> {
    timer_progress(image, fixture, false, false)
}

#[cfg(feature = "test-support")]
pub fn clock_jump(image: &Path, fixture: &Path) -> Result<(), String> {
    timer_progress(image, fixture, true, false)
}

#[cfg(feature = "test-support")]
pub fn timer_mutation_detected(image: &Path, fixture: &Path) -> Result<(), String> {
    match timer_progress(image, fixture, false, true) {
        Err(message) if message == "valid control traffic starved the original native deadline" => {
            Ok(())
        }
        other => Err(format!(
            "disabled guardian timer mutation escaped its deadline oracle: {other:?}"
        )),
    }
}

#[cfg(feature = "test-support")]
fn timer_progress(
    image: &Path,
    fixture: &Path,
    jump: bool,
    disable_timer: bool,
) -> Result<(), String> {
    let observed_start = Instant::now();
    let start = crate::macos_deadline::continuous_nanos().map_err(|error| error.to_string())?;
    let work = crate::macos_deadline::add(start, Duration::from_secs(if jump { 30 } else { 2 }))
        .map_err(|error| error.to_string())?;
    let end = Instant::now() + Duration::from_secs(6);
    let mut attempt = launch_with_deadline(
        &CommandSpec::new(fixture).args(["spin"]),
        image,
        Instant::now() + Duration::from_secs(2),
        end,
        Some(work),
        Duration::ZERO,
    )
    .map_err(|error| {
        format!(
            "control flood launch: {} ({:?})",
            error.error, error.diagnostic
        )
    })?;
    let shared = attempt
        .guardian
        .channel
        .as_ref()
        .expect("guardian control")
        .clone();
    {
        let mut channel = shared.lock().map_err(|_| "guardian channel poisoned")?;
        channel
            .send(Message::InterruptClock, end)
            .map_err(|error| error.to_string())?;
        channel
            .expect(Message::ClockInterruptible, end)
            .map_err(|error| error.to_string())?;
        if jump {
            channel
                .send(
                    Message::AdvanceClock {
                        nanos: u64::try_from(Duration::from_secs(30).as_nanos())
                            .expect("bounded fixture jump"),
                    },
                    end,
                )
                .map_err(|error| error.to_string())?;
        }
        if disable_timer {
            channel
                .send(Message::DisableWorkTimer, end)
                .map_err(|error| error.to_string())?;
        }
    }
    let guardian_pid = attempt.guardian.child.pid;
    let interrupts = std::thread::spawn(move || -> Result<(), String> {
        for _ in 0..2200 {
            // The unreaped native guardian remains owned until this sender joins.
            if unsafe { libc::kill(guardian_pid, libc::SIGUSR2) } != 0 {
                return Err(io::Error::last_os_error().to_string());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    });
    let producer = shared.clone();
    let flood = std::thread::spawn(move || -> Result<(), String> {
        let mut channel = producer.lock().map_err(|_| "guardian channel poisoned")?;
        for _ in 0..320 {
            channel
                .send(Message::Heartbeat, end)
                .map_err(|error| error.to_string())?;
            // Keep valid traffic present across the work boundary and mutation
            // observation without allowing heartbeat loss to mask a disabled timer.
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    });
    let observation_deadline = if jump {
        Instant::now() + Duration::from_millis(500)
    } else {
        observed_start + Duration::from_millis(2500)
    };
    let mut expired_without_termination = false;
    while !crate::macos_watchdog::fixture_root_exited(attempt.child.pid)
        .map_err(|error| error.to_string())?
    {
        if Instant::now() >= observation_deadline {
            expired_without_termination = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    // Close the lease after observing native termination, then require the
    // guardian's successful reap; the fixture never kills the workload itself.
    flood
        .join()
        .map_err(|_| "control flood producer panicked")??;
    interrupts
        .join()
        .map_err(|_| "native interruption producer panicked")??;
    drop(attempt.child);
    attempt.guardian.channel.take();
    drop(shared);
    attempt
        .guardian
        .child
        .retire(end)
        .map_err(|error| error.to_string())?;
    if !attempt
        .guardian
        .child
        .status
        .is_some_and(|status| status.success())
    {
        return Err("control flood did not finish with complete owned retirement".into());
    }
    if expired_without_termination {
        return Err("valid control traffic starved the original native deadline".into());
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub fn resource_recovery(image: &Path) -> Result<(), String> {
    let drain = Instant::now() + Duration::from_secs(2);
    while CHILDREN
        .iter()
        .any(|slot| slot.load(Ordering::Acquire) != 0)
    {
        if Instant::now() >= drain {
            return Err("preexisting native reaping obligations did not retire".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut reserved = Vec::new();
    while let Ok(slot) = reserve() {
        reserved.push(slot);
    }
    let exhausted = reserved.len() == CHILDREN.len();
    let capacity_deadline = Instant::now() + Duration::from_millis(250);
    let rejected = launch(
        &CommandSpec::new(image).args(["__execution-probe"]),
        image,
        capacity_deadline,
        capacity_deadline,
    );
    for slot in reserved {
        CHILDREN[slot].store(0, Ordering::Release);
    }
    match rejected {
        Err(error)
            if error.diagnostic.guardian_pid.is_none()
                && error.diagnostic.launcher_pid.is_none()
                && !error.diagnostic.release_sent => {}
        _ => return Err("capacity exhaustion did not reject before native creation".into()),
    }
    if !exhausted {
        return Err("child capacity was not exactly the bounded runtime inventory".into());
    }
    let descriptor_count = || {
        std::fs::read_dir("/dev/fd")
            .map(|entries| entries.count())
            .map_err(|error| error.to_string())
    };
    let baseline = descriptor_count()?;
    for _ in 0..12 {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut attempt = launch(
            &CommandSpec::new(image).args(["__execution-probe"]),
            image,
            deadline,
            deadline,
        )
        .map_err(|error| error.error.to_string())?;
        attempt
            .child
            .retire(deadline)
            .map_err(|error| error.to_string())?;
        attempt
            .guardian
            .disarm(deadline)
            .map_err(|error| error.to_string())?;
        let diagnostic = startup_fault(
            &CommandSpec::new(image).args(["__execution-probe"]),
            image,
            LaunchFault::GuardianBeforeArm,
        )?;
        if diagnostic.release_sent {
            return Err("failed fixture released target".into());
        }
    }
    let retained = CHILDREN
        .iter()
        .filter(|slot| slot.load(Ordering::Acquire) != 0)
        .count();
    let current = descriptor_count()?;
    if retained != 0 || current != baseline {
        return Err(format!(
            "repeated launch/failure leaked native child slots or private descriptors: retained={retained}, descriptors={current}, baseline={baseline}"
        ));
    }
    Ok(())
}
