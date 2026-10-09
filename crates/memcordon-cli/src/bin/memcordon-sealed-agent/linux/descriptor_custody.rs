//! Descriptor custody for the private TCP profile.
//!
//! The provider owns all six pipe ends. The target receives only the read end
//! of stdin and the write ends of stdout/stderr; the provider keeps their
//! complements for a byte relay to the authenticated frontend. Launch admission
//! and native lifecycle ownership are checked separately by the provider.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Instant;

const GATED_FDS: [RawFd; 5] = [0, 1, 2, 3, 4];
const ENTRY_FDS: [RawFd; 3] = [0, 1, 2];

/// The three pipe ends installed in the single-threaded gated target.
pub struct TargetPipeStdio {
    stdin: OwnedFd,
    stdout: OwnedFd,
    stderr: OwnedFd,
}

/// Provider-owned complements of the target's pipes. The supervising provider
/// must account for these three owners through target retirement.
pub struct ProviderPipeStdio {
    stdin: OwnedFd,
    stdout: OwnedFd,
    stderr: OwnedFd,
}

/// Owned relay streams, deliberately independent of the frontend's object
/// types. The supervisor may pump them concurrently with its own cancellation
/// and lifetime policy; no target descriptor aliases a frontend socket.
pub struct ProviderRelayStreams {
    stdin_writer: Option<File>,
    pub stdout_reader: File,
    pub stderr_reader: File,
}

impl ProviderRelayStreams {
    pub fn take_stdin_writer(&mut self) -> Option<File> {
        self.stdin_writer.take()
    }

    /// Copies through the provider pipe and closes its write end even when
    /// copying fails, so the target cannot wait forever for an absent EOF.
    pub fn copy_stdin_from(&mut self, source: &mut impl Read) -> io::Result<u64> {
        let mut writer = self.take_stdin_writer().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "stdin relay already closed")
        })?;
        io::copy(source, &mut writer)
    }

    pub fn copy_stdout_to(&mut self, destination: &mut impl Write) -> io::Result<u64> {
        io::copy(&mut self.stdout_reader, destination)
    }

    pub fn copy_stderr_to(&mut self, destination: &mut impl Write) -> io::Result<u64> {
        io::copy(&mut self.stderr_reader, destination)
    }
}

impl ProviderPipeStdio {
    /// Exact provider-owned complements that a forked namespace init must
    /// close before waiting for its target. Retaining any writer would hide
    /// EOF from the supervising provider.
    pub fn descriptor_numbers(&self) -> [std::os::fd::RawFd; 3] {
        [
            self.stdin.as_raw_fd(),
            self.stdout.as_raw_fd(),
            self.stderr.as_raw_fd(),
        ]
    }

    pub fn into_relay_streams(self) -> ProviderRelayStreams {
        ProviderRelayStreams {
            stdin_writer: Some(self.stdin.into()),
            stdout_reader: self.stdout.into(),
            stderr_reader: self.stderr.into(),
        }
    }
}

/// Creates anonymous byte pipes without accepting any frontend fd as target
/// stdio. All returned descriptors are moved above the reserved gated slots.
pub fn provider_owned_byte_pipes() -> io::Result<(TargetPipeStdio, ProviderPipeStdio)> {
    let (stdin_read, stdin_write) = byte_pipe()?;
    let (stdout_read, stdout_write) = byte_pipe()?;
    let (stderr_read, stderr_write) = byte_pipe()?;
    let target = TargetPipeStdio {
        stdin: stdin_read,
        stdout: stdout_write,
        stderr: stderr_write,
    };
    let provider = ProviderPipeStdio {
        stdin: stdin_write,
        stdout: stdout_read,
        stderr: stderr_read,
    };
    target.verify_native_directions()?;
    verify_pipe_end(provider.stdin.as_raw_fd(), libc::O_WRONLY)?;
    verify_pipe_end(provider.stdout.as_raw_fd(), libc::O_RDONLY)?;
    verify_pipe_end(provider.stderr.as_raw_fd(), libc::O_RDONLY)?;
    Ok((target, provider))
}

impl TargetPipeStdio {
    pub fn stdin_fd(&self) -> BorrowedFd<'_> {
        self.stdin.as_fd()
    }

    pub fn stdout_fd(&self) -> BorrowedFd<'_> {
        self.stdout.as_fd()
    }

    pub fn stderr_fd(&self) -> BorrowedFd<'_> {
        self.stderr.as_fd()
    }

    pub fn verify_native_directions(&self) -> io::Result<()> {
        verify_pipe_end(self.stdin.as_raw_fd(), libc::O_RDONLY)?;
        verify_pipe_end(self.stdout.as_raw_fd(), libc::O_WRONLY)?;
        verify_pipe_end(self.stderr.as_raw_fd(), libc::O_WRONLY)
    }

    /// Called only in the single-threaded trusted child before sealing its
    /// gated descriptor table. Failure is fatal to that child: partial dup2
    /// success must never be used as a candidate launch.
    pub fn install_at_standard_fds(self) -> io::Result<()> {
        self.verify_native_directions()?;
        for (source, target) in [
            (self.stdin.as_raw_fd(), 0),
            (self.stdout.as_raw_fd(), 1),
            (self.stderr.as_raw_fd(), 2),
        ] {
            // SAFETY: source is a live, owned pipe descriptor above the gated
            // slots; dup2 atomically replaces the selected standard fd.
            if unsafe { libc::dup2(source, target) } == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        drop(self);
        for (fd, direction) in [
            (0, libc::O_RDONLY),
            (1, libc::O_WRONLY),
            (2, libc::O_WRONLY),
        ] {
            verify_pipe_end(fd, direction)?;
            if descriptor_flags(fd)? & libc::FD_CLOEXEC != 0 {
                return Err(invalid_data("target stdio closes on exec"));
            }
        }
        Ok(())
    }

    /// Constructs the entire private gated table in the single-threaded
    /// trusted child. The caller must terminate that child on any error;
    /// partial descriptor installation is never a recoverable launch state.
    pub fn seal_gated_table(
        self,
        target_control: OwnedFd,
        verified_elf: OwnedFd,
    ) -> io::Result<OwnedFd> {
        verify_control_socket(target_control.as_raw_fd())?;
        let elf = native_stat(verified_elf.as_raw_fd())?;
        if elf.st_mode & libc::S_IFMT != libc::S_IFREG
            || status_flags(verified_elf.as_raw_fd())? & libc::O_ACCMODE != libc::O_RDONLY
        {
            return Err(invalid_data(
                "fd 4 is not a read-only regular ELF descriptor",
            ));
        }
        let control_identity = ObjectIdentity::from_fd(target_control.as_raw_fd())?;
        let elf_identity = ObjectIdentity::from_fd(verified_elf.as_raw_fd())?;
        // Move both owned authorities above the reserved slots before stdio
        // replacement, even when an inherited source originally occupied 0–4.
        let control = move_above_gate(target_control)?;
        let elf = move_above_gate(verified_elf)?;
        self.install_at_standard_fds()?;
        for (source, target) in [(control.as_raw_fd(), 3), (elf.as_raw_fd(), 4)] {
            // SAFETY: source is a live duplicate above the gated slots and
            // dup3 atomically installs CLOEXEC into the selected target slot.
            if unsafe { libc::dup3(source, target, libc::O_CLOEXEC) } == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        drop((control, elf));
        // SAFETY: the single-threaded child has arranged exactly fd 0–4 and
        // passes the kernel's documented inclusive range to close_range.
        if unsafe { libc::syscall(libc::SYS_close_range, 5_u32, u32::MAX, 0_u32) } == -1 {
            return Err(io::Error::last_os_error());
        }
        for fd in ENTRY_FDS {
            let direction = if fd == 0 {
                libc::O_RDONLY
            } else {
                libc::O_WRONLY
            };
            verify_pipe_end(fd, direction)?;
            if descriptor_flags(fd)? & libc::FD_CLOEXEC != 0 {
                return Err(invalid_data("gated stdio unexpectedly closes on exec"));
            }
        }
        verify_control_socket(3)?;
        if ObjectIdentity::from_fd(3)? != control_identity {
            return Err(invalid_data("gated control identity mismatch"));
        }
        let installed_elf = native_stat(4)?;
        if installed_elf.st_mode & libc::S_IFMT != libc::S_IFREG
            || status_flags(4)? & libc::O_ACCMODE != libc::O_RDONLY
            || ObjectIdentity::from_fd(4)? != elf_identity
        {
            return Err(invalid_data("gated ELF descriptor mismatch"));
        }
        if descriptor_flags(3)? & libc::FD_CLOEXEC == 0
            || descriptor_flags(4)? & libc::FD_CLOEXEC == 0
        {
            return Err(invalid_data("gated transient descriptor lacks CLOEXEC"));
        }
        // SAFETY: dup3 created the exact fd-4 executable slot, and no other
        // OwnedFd retains ownership after the source was moved and dropped.
        Ok(unsafe { OwnedFd::from_raw_fd(4) })
    }

    fn fds(&self) -> [RawFd; 3] {
        [
            self.stdin.as_raw_fd(),
            self.stdout.as_raw_fd(),
            self.stderr.as_raw_fd(),
        ]
    }
}

fn byte_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut raw = [-1_i32; 2];
    // SAFETY: pipe2 initializes both slots on success and sets CLOEXEC before
    // either descriptor can be observed by another thread.
    if unsafe { libc::pipe2(raw.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pipe2 yielded two unique owned descriptors.
    let read = unsafe { OwnedFd::from_raw_fd(raw[0]) };
    // SAFETY: successful pipe2 yielded two unique owned descriptors.
    let write = unsafe { OwnedFd::from_raw_fd(raw[1]) };
    Ok((move_above_gate(read)?, move_above_gate(write)?))
}

fn move_above_gate(fd: OwnedFd) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC duplicates this live fd into the first slot at
    // or above five, never one of the gated target slots.
    let duplicated = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
    if duplicated == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful F_DUPFD_CLOEXEC returned one newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn native_stat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: zeroed is a valid output buffer for fstat, which initializes it
    // before success is reported.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: stat is writable and fd is supplied by the caller for readback.
    if unsafe { libc::fstat(fd, &raw mut stat) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat)
}

fn status_flags(fd: RawFd) -> io::Result<i32> {
    // SAFETY: F_GETFL reads flags from a borrowed descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags)
}

fn descriptor_flags(fd: RawFd) -> io::Result<i32> {
    // SAFETY: F_GETFD reads close-on-exec from a borrowed descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags)
}

/// Native, object-type and access-mode check. A socket-valued inherited stdio
/// descriptor fails because its file type is not FIFO even if it can carry
/// bytes and reports a superficially compatible access mode.
pub fn verify_pipe_end(fd: RawFd, direction: i32) -> io::Result<()> {
    let stat = native_stat(fd)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err(invalid_data("target stdio is not an anonymous byte pipe"));
    }
    if status_flags(fd)? & libc::O_ACCMODE != direction {
        return Err(invalid_data("target stdio pipe direction mismatch"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
    kind: u32,
}

impl ObjectIdentity {
    fn from_fd(fd: RawFd) -> io::Result<Self> {
        let stat = native_stat(fd)?;
        Ok(Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            kind: stat.st_mode & libc::S_IFMT,
        })
    }

    fn from_proc_fd(path: &Path) -> io::Result<Self> {
        let stat = fs::metadata(path)?;
        Ok(Self {
            device: stat.dev(),
            inode: stat.ino(),
            kind: stat.mode() & libc::S_IFMT,
        })
    }
}

/// Parent-held identities captured before the target duplicates its pipes and
/// seals fd 0–4. The ELF is separately verified for installation provenance
/// by the entrypoint authority code; this type only checks descriptor custody.
pub struct ExpectedGatedDescriptorInventory {
    objects: [ObjectIdentity; 5],
    provider_control: ObjectIdentity,
}

impl ExpectedGatedDescriptorInventory {
    pub(super) fn rebind_private_root_executable(
        &mut self,
        verified_elf: BorrowedFd<'_>,
    ) -> io::Result<()> {
        let elf = native_stat(verified_elf.as_raw_fd())?;
        if elf.st_mode & libc::S_IFMT != libc::S_IFREG
            || status_flags(verified_elf.as_raw_fd())? & libc::O_ACCMODE != libc::O_RDONLY
        {
            return Err(invalid_data(
                "private root executable descriptor is not readonly regular content",
            ));
        }
        self.objects[4] = ObjectIdentity::from_fd(verified_elf.as_raw_fd())?;
        Ok(())
    }
    pub fn capture(
        target: &TargetPipeStdio,
        provider_control: BorrowedFd<'_>,
        target_control: BorrowedFd<'_>,
        verified_elf: BorrowedFd<'_>,
    ) -> io::Result<Self> {
        target.verify_native_directions()?;
        verify_control_socket(provider_control.as_raw_fd())?;
        verify_control_socket(target_control.as_raw_fd())?;
        let elf = native_stat(verified_elf.as_raw_fd())?;
        if elf.st_mode & libc::S_IFMT != libc::S_IFREG
            || status_flags(verified_elf.as_raw_fd())? & libc::O_ACCMODE != libc::O_RDONLY
        {
            return Err(invalid_data(
                "fd 4 is not a read-only regular ELF descriptor",
            ));
        }
        let pipes = target.fds();
        Ok(Self {
            objects: [
                ObjectIdentity::from_fd(pipes[0])?,
                ObjectIdentity::from_fd(pipes[1])?,
                ObjectIdentity::from_fd(pipes[2])?,
                ObjectIdentity::from_fd(target_control.as_raw_fd())?,
                ObjectIdentity::from_fd(verified_elf.as_raw_fd())?,
            ],
            provider_control: ObjectIdentity::from_fd(provider_control.as_raw_fd())?,
        })
    }
}

fn verify_control_socket(fd: RawFd) -> io::Result<()> {
    let control = native_stat(fd)?;
    if control.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(invalid_data("control authority is not a socket"));
    }
    if socket_option(fd, libc::SO_DOMAIN)? != libc::AF_UNIX
        || socket_option(fd, libc::SO_TYPE)? != libc::SOCK_SEQPACKET
    {
        return Err(invalid_data("control authority is not AF_UNIX seqpacket"));
    }
    Ok(())
}

fn socket_option(fd: RawFd, option: i32) -> io::Result<i32> {
    let mut domain = 0_i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `length` bytes into a live i32.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&raw mut domain).cast(),
            &raw mut length,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<i32>() {
        return Err(invalid_data("control socket option length mismatch"));
    }
    Ok(domain)
}

/// Unforgeable-by-construction inside this module: a proof is returned only
/// after a native `/proc/<pid>/fd` readback of the exact gated table.
pub struct GatedDescriptorProof {
    pid: libc::pid_t,
    expected: ExpectedGatedDescriptorInventory,
}

/// Binds the gated five-fd inventory to an observed successful exec boundary.
/// The kernel then closes fd 3 and 4 because both had CLOEXEC, leaving only
/// the three provider-owned byte-pipe stdio descriptors at target entry.
pub struct PostExecDescriptorProof {
    pid: libc::pid_t,
    entry_fds: [RawFd; 3],
}

impl PostExecDescriptorProof {
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    pub fn entry_fds(&self) -> &[RawFd; 3] {
        &self.entry_fds
    }
}

pub fn verify_private_gated_descriptor_inventory(
    pid: libc::pid_t,
    expected: ExpectedGatedDescriptorInventory,
) -> io::Result<GatedDescriptorProof> {
    if pid <= 0 {
        return Err(invalid_data("invalid gated target pid"));
    }
    let process = Path::new("/proc").join(pid.to_string());
    let mut actual = fs::read_dir(process.join("fd"))?
        .map(|item| {
            let name = item?.file_name();
            name.to_string_lossy()
                .parse::<RawFd>()
                .map_err(|_| invalid_data("nonnumeric gated descriptor name"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    actual.sort_unstable();
    if actual != GATED_FDS {
        return Err(invalid_data(
            "gated descriptor inventory differs from sealed mode",
        ));
    }
    for (index, fd) in GATED_FDS.into_iter().enumerate() {
        let fd_path = process.join("fd").join(fd.to_string());
        if ObjectIdentity::from_proc_fd(&fd_path)? != expected.objects[index] {
            return Err(invalid_data("gated descriptor object identity mismatch"));
        }
        let flags = proc_fd_flags(&process.join("fdinfo").join(fd.to_string()))?;
        let access = flags & libc::O_ACCMODE;
        let required_access = match fd {
            0 | 4 => libc::O_RDONLY,
            1 | 2 => libc::O_WRONLY,
            3 => libc::O_RDWR,
            _ => unreachable!(),
        };
        if access != required_access {
            return Err(invalid_data("gated descriptor direction mismatch"));
        }
        let must_close = fd >= 3;
        if (flags & libc::O_CLOEXEC != 0) != must_close {
            return Err(invalid_data("gated descriptor CLOEXEC mismatch"));
        }
    }
    Ok(GatedDescriptorProof { pid, expected })
}

fn proc_fd_flags(path: &Path) -> io::Result<i32> {
    let info = fs::read_to_string(path)?;
    let mut found = None;
    for line in info.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key != "flags" {
            continue;
        }
        if found.is_some() {
            return Err(invalid_data("duplicate descriptor flags"));
        }
        found = Some(
            i32::from_str_radix(value.trim(), 8)
                .map_err(|_| invalid_data("invalid descriptor flags"))?,
        );
    }
    found.ok_or_else(|| invalid_data("missing descriptor flags"))
}

/// Native objects captured in the namespace parent before its trusted fork.
pub struct ExpectedPrivateExecState {
    elf: OwnedFd,
    stdio: [ObjectIdentity; 3],
    identity: super::execution_identity::ResolvedTargetIdentity,
}

impl ExpectedPrivateExecState {
    pub fn capture(
        elf: BorrowedFd<'_>,
        stdio: &TargetPipeStdio,
        identity: super::execution_identity::ResolvedTargetIdentity,
    ) -> io::Result<Self> {
        let fds = stdio.fds();
        Ok(Self {
            elf: elf.try_clone_to_owned()?,
            stdio: [
                ObjectIdentity::from_fd(fds[0])?,
                ObjectIdentity::from_fd(fds[1])?,
                ObjectIdentity::from_fd(fds[2])?,
            ],
            identity,
        })
    }
}

/// Runtime-only tracer belonging to the actual namespace parent task. It
/// cannot be transferred to another worker or constructed from a saved record.
pub struct PrivateExecObserver {
    child: libc::pid_t,
    task: libc::pid_t,
    pidfd: OwnedFd,
    expected: ExpectedPrivateExecState,
    traced: bool,
    affinity: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl PrivateExecObserver {
    pub fn observe_initial_stop(
        child: libc::pid_t,
        pidfd: BorrowedFd<'_>,
        expected: ExpectedPrivateExecState,
        deadline: Instant,
    ) -> io::Result<Self> {
        if child <= 0 {
            return Err(invalid_data("invalid direct child"));
        }
        let mut observer = Self {
            child,
            task: unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t,
            pidfd: pidfd.try_clone_to_owned()?,
            expected,
            traced: true,
            affinity: std::marker::PhantomData,
        };
        let status = observer.wait_event(Some(deadline))?;
        if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGSTOP || status >> 16 != 0
        {
            return Err(invalid_data(
                "trusted child did not enter its initial trace stop",
            ));
        }
        observer.trace(
            libc::PTRACE_SETOPTIONS,
            (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as usize,
        )?;
        observer.trace(libc::PTRACE_CONT, 0)?;
        Ok(observer)
    }

    fn trace(&self, request: libc::c_uint, data: usize) -> io::Result<()> {
        if unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t != self.task {
            return Err(invalid_data("native exec tracer changed owner task"));
        }
        if unsafe {
            libc::ptrace(
                request,
                self.child,
                std::ptr::null_mut::<libc::c_void>(),
                data as *mut libc::c_void,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn wait_event(&mut self, deadline: Option<Instant>) -> io::Result<i32> {
        loop {
            if unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t != self.task {
                return Err(invalid_data("native exec wait changed owner task"));
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native exec-stop deadline",
                ));
            }
            let mut status = 0;
            let result =
                unsafe { libc::waitpid(self.child, &raw mut status, libc::__WALL | libc::WNOHANG) };
            if result == self.child {
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    self.traced = false;
                    return Err(invalid_data("trusted child exited without an exec event"));
                }
                return Ok(status);
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    pub fn observe_exec_and_detach(
        &mut self,
        deadline: Option<Instant>,
    ) -> io::Result<PostExecDescriptorProof> {
        let proof = self.observe_exec_stop(deadline)?;
        self.trace(libc::PTRACE_DETACH, 0)?;
        self.traced = false;
        Ok(proof)
    }

    #[cfg(test)]
    pub fn observe_exec_and_detach_with_observer(
        &mut self,
        deadline: Instant,
        at_exec_stop: impl FnOnce(),
    ) -> io::Result<PostExecDescriptorProof> {
        let proof = self.observe_exec_stop(Some(deadline))?;
        at_exec_stop();
        self.trace(libc::PTRACE_DETACH, 0)?;
        self.traced = false;
        Ok(proof)
    }

    fn observe_exec_stop(
        &mut self,
        deadline: Option<Instant>,
    ) -> io::Result<PostExecDescriptorProof> {
        let status = self.wait_event(deadline)?;
        if !libc::WIFSTOPPED(status)
            || libc::WSTOPSIG(status) != libc::SIGTRAP
            || status >> 16 != libc::PTRACE_EVENT_EXEC
        {
            return Err(invalid_data("unexpected native stop before exec"));
        }
        // pidfd fdinfo translates the exact held child into the mounted procfs
        // namespace; waitpid above deliberately uses the parent's local PID.
        let contents = fs::read_to_string(
            Path::new("/proc/self/fdinfo").join(self.pidfd.as_raw_fd().to_string()),
        )?;
        let mut pids = contents
            .lines()
            .filter_map(|line| line.strip_prefix("Pid:"));
        let pid = pids
            .next()
            .ok_or_else(|| invalid_data("held pidfd has no proc PID"))?
            .trim()
            .parse::<libc::pid_t>()
            .map_err(|_| invalid_data("invalid held proc PID"))?;
        if pid <= 0 || pids.next().is_some() {
            return Err(invalid_data("ambiguous held proc PID"));
        }
        let process = Path::new("/proc").join(pid.to_string());
        if ObjectIdentity::from_proc_fd(&process.join("exe"))?
            != ObjectIdentity::from_fd(self.expected.elf.as_raw_fd())?
        {
            return Err(invalid_data("kernel exec event selected another ELF"));
        }
        let table = process.join("fd");
        let mut actual = std::collections::BTreeSet::new();
        for entry in fs::read_dir(&table)? {
            let entry = entry?;
            let fd = entry
                .file_name()
                .to_str()
                .ok_or_else(|| invalid_data("non-numeric entry fd"))?
                .parse::<i32>()
                .map_err(|_| invalid_data("non-numeric entry fd"))?;
            if !(0..=2).contains(&fd) {
                return Err(invalid_data("control or ELF descriptor survived exec"));
            }
            if ObjectIdentity::from_proc_fd(&entry.path())? != self.expected.stdio[fd as usize] {
                return Err(invalid_data("postexec stdio object changed"));
            }
            actual.insert(fd);
        }
        if actual != std::collections::BTreeSet::from([0, 1, 2]) {
            return Err(invalid_data("postexec stdio incomplete"));
        }
        let status = fs::read_to_string(process.join("status"))?;
        let observed = super::envelope::parse_proc_status(&status)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let mut groups = observed.supplementary_groups;
        groups.sort_unstable();
        if observed.uids != [self.expected.identity.uid(); 4]
            || observed.gids != [self.expected.identity.gid(); 4]
            || groups != self.expected.identity.groups()
            || !observed.no_new_privs
            || observed.capability_inheritable_set != 0
            || observed.capability_permitted_set != 0
            || observed.capability_effective_set != 0
            || observed.capability_bounding_set != 0
            || observed.capability_ambient_set != 0
        {
            return Err(invalid_data(
                "postexec credentials or capability state differs",
            ));
        }
        Ok(PostExecDescriptorProof {
            pid,
            entry_fds: ENTRY_FDS,
        })
    }
}

impl Drop for PrivateExecObserver {
    fn drop(&mut self) {
        if self.traced {
            // The exact owned pidfd avoids numeric PID signalling after error.
            // Init retains wait ownership; EXITKILL also applies until detach.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
        }
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
