//! Private native launch protocol. No target code runs before guardian arming.
use std::ffi::{CString, OsString};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use memcordon_core::CommandSpec;
use serde::{Deserialize, Serialize};

const STARTUP: Duration = Duration::from_secs(5);
const FRAME_LIMIT: usize = 256;
const RESERVED: i32 = i32::MIN;
static CHILDREN: [AtomicI32; 256] = [const { AtomicI32::new(0) }; 256];
static DEPENDENCIES: [AtomicI32; 256] = [const { AtomicI32::new(0) }; 256];
static REAPER: OnceLock<Result<(), String>> = OnceLock::new();

/// Slots are reserved before spawn. Drop transfers an unreaped PID by one atomic
/// store to the permanent runtime, without allocation, locking, killing or waiting.
pub(crate) struct Child {
    pid: i32,
    slot: usize,
    status: Option<ExitStatus>,
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
        if self.status.is_none() {
            CHILDREN[self.slot].store(-self.pid, Ordering::Release);
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Message {
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
    message: Message,
}

struct Channel {
    stream: UnixStream,
    run: u64,
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
        Ok(Self { stream, run })
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
            version: 1,
            run: self.run,
            message,
        })?;
        if bytes.len() > FRAME_LIMIT {
            return Err(io::Error::other("private launch frame exceeds bound"));
        }
        self.transfer(&mut (bytes.len() as u16).to_be_bytes(), true, deadline)?;
        self.transfer(&mut bytes, true, deadline)?;
        Ok(())
    }
    fn receive(&mut self, deadline: Instant) -> io::Result<Option<Message>> {
        let mut length = [0; 2];
        if !self.transfer(&mut length, false, deadline)? {
            return Ok(None);
        }
        let length = usize::from(u16::from_be_bytes(length));
        if length == 0 || length > FRAME_LIMIT {
            return Err(io::Error::other("invalid private launch frame length"));
        }
        let mut bytes = [0; FRAME_LIMIT];
        if !self.transfer(&mut bytes[..length], false, deadline)? {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "missing private launch frame",
            ));
        }
        let frame: Frame = serde_json::from_slice(&bytes[..length])?;
        if frame.version != 1 || frame.run != self.run {
            return Err(io::Error::other("private launch protocol binding mismatch"));
        }
        Ok(Some(frame.message))
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
    crate::macos_watchdog::inspect_until(deadline, move || {
        Ok(native_spawn_owned(
            &path,
            &args,
            endpoint,
            quiet,
            source,
            environment,
        ))
    })
    .map_err(|message| io::Error::new(io::ErrorKind::TimedOut, message))?
}

fn native_spawn_owned(
    path: &Path,
    args: &[OsString],
    endpoint: RawFd,
    quiet: bool,
    source: std::os::fd::OwnedFd,
    environment: Vec<(OsString, OsString)>,
) -> io::Result<Child> {
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
                if quiet {
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
                check(libc::posix_spawnattr_setpgroup(&mut attributes, 0))?;
                check(libc::posix_spawnattr_setflags(
                    &mut attributes,
                    libc::POSIX_SPAWN_SETPGROUP as i16,
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
    channel: Option<Channel>,
    child: Child,
}
impl Guardian {
    pub(crate) fn alive(&self) -> io::Result<()> {
        if self.child.observe()?.is_none() {
            Ok(())
        } else {
            Err(io::Error::other(
                "guardian exited before workload retirement",
            ))
        }
    }
    pub(crate) fn disarm(mut self, deadline: Instant) -> io::Result<()> {
        let mut channel = self.channel.take().expect("live guardian lease");
        channel.send(Message::Disarm, deadline)?;
        channel.expect(Message::Retired, deadline)?;
        drop(channel);
        self.child.retire(deadline)
    }
}

pub(crate) struct Launch {
    pub(crate) child: Child,
    pub(crate) guardian: Guardian,
    pub(crate) authorized: Instant,
}
pub(crate) struct StartupError {
    pub(crate) phase: &'static str,
    pub(crate) error: io::Error,
    pub(crate) diagnostic: memcordon_core::NativeStartupDiagnosticV1,
    pub(crate) authorized: Option<Instant>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum LaunchFault {
    GuardianBeforeArm,
    GuardianAfterArm,
    LauncherBeforeExec,
}

pub(crate) fn launch(
    command: &CommandSpec,
    image: &Path,
    deadline: Instant,
    cleanup_deadline: Instant,
) -> Result<Launch, Box<StartupError>> {
    launch_inner(command, image, deadline, cleanup_deadline, None)
}

fn launch_inner(
    command: &CommandSpec,
    image: &Path,
    deadline: Instant,
    cleanup_deadline: Instant,
    fault: Option<LaunchFault>,
) -> Result<Launch, Box<StartupError>> {
    use memcordon_core::{
        NativeArgument, NativeHelperIdentityV1, NativeStartupCleanupErrorV1,
        NativeStartupCleanupStateV1 as CleanupState, NativeStartupCleanupV1,
        NativeStartupDiagnosticV1, NativeStartupOperationV1 as Operation,
        NativeStartupPhaseV1 as Phase,
    };
    use std::os::unix::fs::MetadataExt;
    let requested = image.to_owned();
    let context = crate::macos_watchdog::inspect_until(deadline, move || {
        Ok((
            std::fs::canonicalize(&requested).ok(),
            std::fs::metadata(&requested).ok(),
            std::env::current_dir().ok(),
        ))
    })
    .ok();
    let mut diagnostic = NativeStartupDiagnosticV1 {
        schema_version: 1,
        requested_helper: NativeArgument::from_os(image.as_os_str()),
        canonical_helper: context
            .as_ref()
            .and_then(|(path, _, _)| path.as_ref())
            .map(|path| NativeArgument::from_os(path.as_os_str())),
        helper_identity: context
            .as_ref()
            .filter(|(canonical, _, _)| canonical.is_some())
            .and_then(|(_, metadata, _)| metadata.as_ref())
            .map(|metadata| NativeHelperIdentityV1 {
                device: metadata.dev(),
                inode: metadata.ino(),
                size_bytes: metadata.len(),
                sha256: None,
            }),
        cwd: context
            .as_ref()
            .and_then(|(_, _, cwd)| cwd.as_ref())
            .map(|path| NativeArgument::from_os(path.as_os_str())),
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
    let mut phase = "helper-spawn";
    let mut guardian_owner = None;
    let mut child_owner = None;
    let mut exec_failed = false;
    let mut release_time = None;
    let result = (|| {
        let mut run = 0_u64;
        // SAFETY: arc4random_buf initializes the exact local correlation identifier bytes.
        unsafe { libc::arc4random_buf((&mut run as *mut u64).cast(), std::mem::size_of_val(&run)) };
        let (parent, endpoint) = private_pair()?;
        let mut channel = Channel::new(parent, run)?;
        let args = [
            OsString::from("__macos-guardian"),
            endpoint.as_raw_fd().to_string().into(),
            run.to_string().into(),
        ];
        let child = native_spawn(image, &args, endpoint.as_raw_fd(), true, deadline)?;
        diagnostic.guardian_pid = Some(child.id());
        drop(endpoint);
        guardian_owner = Some(Guardian {
            channel: Some(channel),
            child,
        });
        let guardian = guardian_owner.as_mut().expect("guardian created");
        phase = "helper-ready";
        diagnostic.phase = Phase::GuardianReadiness;
        diagnostic.operation = Operation::ReadGuardianReadiness;
        guardian
            .channel
            .as_mut()
            .expect("guardian lease")
            .expect(Message::Ready, deadline)?;
        diagnostic.guardian_ready = true;
        if fault == Some(LaunchFault::GuardianBeforeArm) {
            guardian.child.kill()?;
            guardian.child.retire(deadline)?;
        }
        phase = "launcher-spawn";
        diagnostic.phase = Phase::LauncherSpawn;
        diagnostic.operation = Operation::SpawnLauncher;
        let (parent, endpoint) = private_pair()?;
        channel = Channel::new(parent, run)?;
        let mut args = vec![
            OsString::from("__macos-launcher"),
            endpoint.as_raw_fd().to_string().into(),
            run.to_string().into(),
            OsString::from("--"),
            command.program().to_owned(),
        ];
        args.extend(command.arguments().iter().cloned());
        let child = native_spawn(image, &args, endpoint.as_raw_fd(), false, deadline)?;
        diagnostic.launcher_pid = Some(child.id());
        DEPENDENCIES[child.slot].store(guardian.child.pid, Ordering::Release);
        child_owner = Some(child);
        let child = child_owner.as_mut().expect("launcher created");
        drop(endpoint);
        let result = (|| {
            phase = "launcher-ready";
            diagnostic.phase = Phase::LauncherReadiness;
            diagnostic.operation = Operation::ReadLauncherReadiness;
            channel.expect(Message::Ready, deadline)?;
            phase = "workload-arm";
            diagnostic.phase = Phase::WorkloadBinding;
            diagnostic.operation = Operation::BindWorkload;
            let group = child.pid;
            guardian
                .channel
                .as_mut()
                .expect("guardian lease")
                .send(Message::Bind { group }, deadline)?;
            guardian
                .channel
                .as_mut()
                .expect("guardian lease")
                .expect(Message::Armed { group }, deadline)?;
            if fault == Some(LaunchFault::GuardianAfterArm) {
                guardian.child.kill()?;
                guardian.child.retire(deadline)?;
            }
            guardian.alive()?;
            let witness = ExecWitness::new(group)?;
            if fault == Some(LaunchFault::LauncherBeforeExec) {
                child.kill()?;
            }
            phase = "target-release";
            diagnostic.phase = Phase::TargetRelease;
            diagnostic.operation = Operation::ReleaseTarget;
            let authorized = Instant::now();
            channel.send(Message::Release, deadline)?;
            diagnostic.release_sent = true;
            release_time = Some(authorized);
            phase = "target-exec";
            diagnostic.phase = Phase::TargetExec;
            diagnostic.operation = Operation::ConfirmTargetExec;
            match channel.receive(deadline)? {
                None => {
                    witness.confirm(deadline)?;
                    diagnostic.exec_confirmed = true;
                    Ok(authorized)
                }
                Some(Message::Failure { errno }) => {
                    exec_failed = true;
                    Err(io::Error::from_raw_os_error(errno))
                }
                _ => Err(io::Error::other("unexpected target exec acknowledgement")),
            }
        })();
        drop(channel);
        result
    })();
    match result {
        Ok(authorized) => Ok(Launch {
            child: child_owner.take().expect("successful launcher"),
            guardian: guardian_owner.take().expect("successful guardian"),
            authorized,
        }),
        Err(error) => {
            diagnostic.native_errno = error.raw_os_error();
            let mut record = |operation, result: io::Result<()>| {
                if let Err(error) = result {
                    diagnostic.cleanup.errors.push(NativeStartupCleanupErrorV1 {
                        operation,
                        native_errno: error.raw_os_error(),
                        detail: error.to_string(),
                    });
                }
            };
            if let Some(child) = child_owner.as_ref() {
                record(Operation::TerminateLauncher, child.kill());
            }
            if let Some(guardian) = guardian_owner.as_mut() {
                guardian.channel.take();
                if !diagnostic.release_sent || exec_failed {
                    record(Operation::TerminateGuardian, guardian.child.kill());
                }
                record(
                    Operation::ReapGuardian,
                    guardian.child.retire(cleanup_deadline),
                );
            }
            if let Some(child) = child_owner.as_mut() {
                if guardian_owner
                    .as_ref()
                    .is_none_or(|guardian| guardian.child.status.is_some())
                {
                    record(Operation::ReapLauncher, child.retire(cleanup_deadline));
                } else {
                    record(
                        Operation::ReapLauncher,
                        Err(io::Error::other(
                            "root retained while guardian cleanup remains outstanding",
                        )),
                    );
                }
            }
            let pending_native_spawn = error.kind() == io::ErrorKind::TimedOut
                && matches!(
                    diagnostic.operation,
                    Operation::SpawnGuardian | Operation::SpawnLauncher
                );
            diagnostic.cleanup.state = if diagnostic.cleanup.errors.is_empty()
                && (!diagnostic.release_sent || exec_failed)
                && !pending_native_spawn
            {
                CleanupState::Complete
            } else if !diagnostic.cleanup.errors.is_empty() {
                CleanupState::Incomplete
            } else {
                CleanupState::Unknown
            };
            Err(Box::new(StartupError {
                phase,
                error,
                diagnostic,
                authorized: release_time,
            }))
        }
    }
}

/// Dispatch only after CLI has checked the hidden native arguments.
pub fn helper(guardian: bool, descriptor: RawFd, run: u64, command: &[OsString]) -> i32 {
    if guardian {
        // SAFETY: a stopped guardian's newly orphaned process group receives
        // SIGHUP/SIGCONT when its frontend dies. Preserve the death lease so it
        // can clean observed workload members after that automatic resume.
        if unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) } == libc::SIG_ERR {
            return 126;
        }
    }
    // Validate before constructing an owned descriptor, including direct malformed invocations.
    // SAFETY: F_GETFD only queries descriptor validity.
    if descriptor < 3 || unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
        return 126;
    }
    // SAFETY: the hidden invocation transfers this inherited socket exactly once.
    let stream = unsafe { UnixStream::from_raw_fd(descriptor) };
    // SAFETY: the launcher must never pass its private protocol endpoint to target exec.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return 126;
    }
    let Ok(mut channel) = Channel::new(stream, run) else {
        return 126;
    };
    let deadline = Instant::now() + STARTUP;
    if channel.send(Message::Ready, deadline).is_err() {
        return 126;
    }
    if guardian {
        let Ok(Some(Message::Bind { group })) = channel.receive(deadline) else {
            return 126;
        };
        if group <= 0 {
            return 126;
        }
        let Ok(identity) = crate::macos_watchdog::root_identity(group) else {
            return 126;
        };
        let mut members = std::collections::HashSet::new();
        members.insert(identity);
        if channel.send(Message::Armed { group }, deadline).is_err() {
            crate::macos_watchdog::kill_bound_group(identity);
            return 126;
        }
        loop {
            let mut poll = libc::pollfd {
                fd: descriptor,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: guardian independently waits for its private death-detection lease.
            let result = unsafe { libc::poll(&mut poll, 1, 50) };
            if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if result == 0 {
                crate::macos_watchdog::guardian_members(identity, &mut members);
                continue;
            }
            if result > 0 {
                match channel.receive(Instant::now() + STARTUP) {
                    Ok(Some(Message::Disarm)) => {
                        return if channel
                            .send(Message::Retired, Instant::now() + STARTUP)
                            .is_ok()
                        {
                            0
                        } else {
                            126
                        };
                    }
                    #[cfg(feature = "test-support")]
                    Ok(Some(Message::Snapshot { pid })) => {
                        crate::macos_watchdog::guardian_members(identity, &mut members);
                        let observed = members.iter().any(|member| member.pid == pid);
                        if channel
                            .send(
                                Message::Observed { pid, observed },
                                Instant::now() + STARTUP,
                            )
                            .is_ok()
                        {
                            continue;
                        }
                    }
                    _ => {}
                }
            }
            crate::macos_watchdog::kill_guardian_members(identity, &members);
            return 0;
        }
    }
    if channel.expect(Message::Release, deadline).is_err() {
        return 126;
    }
    let Some((program, arguments)) = command.split_first() else {
        return 126;
    };
    let error = Command::new(program).args(arguments).exec();
    let _ = channel.send(
        Message::Failure {
            errno: error.raw_os_error().unwrap_or(libc::EIO),
        },
        Instant::now() + STARTUP,
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
        let expired: Result<(), String> = inspect_with_admission(
            Instant::now() + Duration::from_millis(20),
            InspectionAdmission::Cleanup,
            || panic!("unadmitted cleanup inspection must not execute"),
        );
        if !expired.is_err_and(|error| error.contains("deadline expired")) {
            return Err("cleanup admission did not respect its deadline".into());
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
    // Both inspector slots remain occupied until the fixture releases the worker.
    // Cleanup must recover without resubmitting any native operation.
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
    result
}

/// Disposable fixture frontend. Its caller kills this process after the atomic
/// identity marker is published; the stopped sibling guardian owns the lease.
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
    let channel = launch
        .guardian
        .channel
        .as_mut()
        .expect("owned guardian lease");
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
    launch
        .child
        .retire(deadline)
        .map_err(|error| error.to_string())?;
    crate::test_support::ProcessIdentity::for_pid(launch.guardian.child.id())
        .and_then(|identity| identity.publish_to(marker))
        .map_err(|error| error.to_string())?;
    loop {
        std::thread::park();
    }
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
    for slot in reserved {
        CHILDREN[slot].store(0, Ordering::Release);
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
    if CHILDREN
        .iter()
        .any(|slot| slot.load(Ordering::Acquire) != 0)
        || descriptor_count()? != baseline
    {
        return Err(
            "repeated launch/failure leaked native child slots or private descriptors".into(),
        );
    }
    Ok(())
}
