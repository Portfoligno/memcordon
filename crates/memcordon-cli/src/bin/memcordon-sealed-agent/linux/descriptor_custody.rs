//! Descriptor custody for the not-yet-routed private TCP profile.
//!
//! The provider owns all six pipe ends. The target receives only the read end
//! of stdin and the write ends of stdout/stderr; the provider keeps their
//! complements for a byte relay to the authenticated frontend. Nothing here
//! makes the private profile available without the remaining launch, admission
//! and native qualification work.

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
            "gated descriptor inventory is not exactly fd 0–4",
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

/// Reads the trusted SOCK_SEQPACKET exec protocol itself. An armed packet
/// followed by EOF is insufficient alone (the stub could die): the pinned ELF
/// must also be the live process executable before entry is certified. A fast
/// exit or replacement exec fails closed. This is intentionally not routed to
/// admission until the full launch and native qualification patch exists.
pub fn observe_private_exec_transition(
    gated: GatedDescriptorProof,
    provider_control: BorrowedFd<'_>,
    expected_armed_packet: &[u8],
    deadline: Instant,
) -> io::Result<PostExecDescriptorProof> {
    if expected_armed_packet.is_empty() {
        return Err(invalid_data("empty exec-armed packet"));
    }
    verify_control_socket(provider_control.as_raw_fd())?;
    if ObjectIdentity::from_fd(provider_control.as_raw_fd())? != gated.expected.provider_control {
        return Err(invalid_data("exec control channel identity mismatch"));
    }
    let armed = receive_control_packet(provider_control, deadline)?
        .ok_or_else(|| invalid_data("control closed before exec-armed packet"))?;
    if armed != expected_armed_packet {
        return Err(invalid_data("exec-armed packet mismatch"));
    }
    if receive_control_packet(provider_control, deadline)?.is_some() {
        return Err(invalid_data(
            "target reported exec failure or trailing control data",
        ));
    }
    verify_private_exec_entry(gated, provider_control)
}

/// Complete the exact pinned-ELF transition after the owner has already
/// decoded the armed/failure control packets, retaining first failure detail.
pub fn verify_private_exec_entry(
    gated: GatedDescriptorProof,
    provider_control: BorrowedFd<'_>,
) -> io::Result<PostExecDescriptorProof> {
    verify_control_socket(provider_control.as_raw_fd())?;
    if ObjectIdentity::from_fd(provider_control.as_raw_fd())? != gated.expected.provider_control {
        return Err(invalid_data("exec control channel identity mismatch"));
    }
    let exe = Path::new("/proc").join(gated.pid.to_string()).join("exe");
    if ObjectIdentity::from_proc_fd(&exe)? != gated.expected.objects[4] {
        return Err(invalid_data("exec did not enter the pinned ELF"));
    }
    Ok(PostExecDescriptorProof {
        pid: gated.pid,
        entry_fds: ENTRY_FDS,
    })
}

fn receive_control_packet(
    control: BorrowedFd<'_>,
    deadline: Instant,
) -> io::Result<Option<Vec<u8>>> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "exec control deadline",
            ));
        }
        let millis = deadline.saturating_duration_since(now).as_millis().max(1);
        let timeout = i32::try_from(millis).unwrap_or(i32::MAX);
        let mut pollfd = libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: pollfd is live for the bounded synchronous call.
        let ready = unsafe { libc::poll(&raw mut pollfd, 1, timeout) };
        if ready == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            continue;
        }
        if pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(invalid_data("exec control socket failed"));
        }
        let mut packet = [0_u8; 64];
        // SAFETY: recv writes into the live bounded buffer. MSG_TRUNC reports
        // the actual packet length so an oversized record cannot be accepted.
        let count = unsafe {
            libc::recv(
                control.as_raw_fd(),
                packet.as_mut_ptr().cast(),
                packet.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if count == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted
                || error.kind() == io::ErrorKind::WouldBlock
            {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Ok(None);
        }
        let count =
            usize::try_from(count).map_err(|_| invalid_data("negative exec packet length"))?;
        if count > packet.len() {
            return Err(invalid_data("oversized exec control packet"));
        }
        return Ok(Some(packet[..count].to_vec()));
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
