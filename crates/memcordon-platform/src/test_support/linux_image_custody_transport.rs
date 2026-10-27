//! Private, bounded Linux capability transport. No pathname or policy authority.
use std::fs::File;
use std::io;
use std::mem::{size_of, size_of_val};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Stdio;
use std::time::Instant;

pub const IMAGE_CUSTODY_PACKET_BOUND: usize = 16 * 1024;
// Larger than the admitted inventory solely to adopt and close rejected extras.
const REJECT_DESCRIPTOR_BOUND: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageCustodyPeer {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

impl ImageCustodyPeer {
    pub fn current() -> Self {
        Self {
            pid: std::process::id(),
            // SAFETY: these read only this process's real kernel credentials.
            uid: unsafe { libc::getuid() },
            // SAFETY: as above, no credential mutation.
            gid: unsafe { libc::getgid() },
        }
    }
}

pub struct ImageCustodyPacket {
    pub bytes: Vec<u8>,
    pub descriptor: Option<File>,
}

pub struct ImageCustodySocket {
    socket: OwnedFd,
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn cutoff(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "image custody original cutoff elapsed",
        ))
    } else {
        Ok(())
    }
}

fn socket_option(socket: &OwnedFd, option: libc::c_int) -> io::Result<libc::c_int> {
    let mut result = 0;
    let mut length = size_of_val(&result) as libc::socklen_t;
    // SAFETY: initialized scalar output and its exact writable size.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&mut result as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of_val(&result) {
        return Err(invalid("image custody socket option size differs"));
    }
    Ok(result)
}

impl ImageCustodySocket {
    /// Both endpoints are close-on-exec and nonblocking. Only into_stdio grants
    /// one endpoint to the explicitly selected child role through native argv.
    pub fn pair() -> io::Result<(Self, Self)> {
        let mut raw = [-1; 2];
        // SAFETY: socketpair writes exactly two owned descriptors on success.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                raw.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: each successful socketpair output transfers one unique owner.
        let first = unsafe { OwnedFd::from_raw_fd(raw[0]) };
        // SAFETY: second unique socketpair output, adopted before fallible work.
        let second = unsafe { OwnedFd::from_raw_fd(raw[1]) };
        for socket in [&first, &second] {
            let enabled: libc::c_int = 1;
            // SAFETY: fixed socket option borrows one initialized integer.
            if unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&enabled as *const libc::c_int).cast(),
                    size_of_val(&enabled) as libc::socklen_t,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok((Self { socket: first }, Self { socket: second }))
    }

    pub fn into_stdio(self) -> Stdio {
        Stdio::from(File::from(self.socket))
    }

    /// Only the closed custodian child entrypoint calls this. Duplicate stdin
    /// close-on-exec, also narrowing the original stdio inheritance flag. The
    /// runtime's original stdin remains live only until that child exits.
    pub fn take_stdin() -> io::Result<Self> {
        // SAFETY: duplicate the inherited descriptor, never adopt an alias of
        // a descriptor another safe stdio abstraction may still borrow.
        let raw = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fcntl transfers one fresh owned descriptor.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let result = Self { socket };
        if socket_option(&result.socket, libc::SO_DOMAIN)? != libc::AF_UNIX
            || socket_option(&result.socket, libc::SO_TYPE)? != libc::SOCK_SEQPACKET
            || socket_option(&result.socket, libc::SO_PASSCRED)? != 1
        {
            return Err(invalid("image custody stdin socket contract differs"));
        }
        // SAFETY: query and narrow inheritance of the same retained descriptor.
        let flags = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: FD_CLOEXEC affects only this owned child transport descriptor.
        if unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: query the open description and retain nonblocking behavior.
        let flags = unsafe { libc::fcntl(result.socket.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_NONBLOCK == 0 {
            return Err(invalid("image custody stdin is blocking"));
        }
        Ok(result)
    }

    fn ready(&self, event: libc::c_short, deadline: Instant) -> io::Result<()> {
        loop {
            cutoff(deadline)?;
            // Short finite polls avoid an uninterruptible large-duration wait.
            let remaining = deadline.saturating_duration_since(Instant::now());
            let millis = remaining.as_millis().min(100) as libc::c_int;
            let mut descriptor = libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events: event,
                revents: 0,
            };
            // SAFETY: one initialized live pollfd, no owner moves during poll.
            let count = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            cutoff(deadline)?;
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(invalid("image custody transport descriptor invalid"));
            }
            if descriptor.revents & event != 0 {
                return Ok(());
            }
            if descriptor.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "image custody peer channel closed",
                ));
            }
        }
    }

    /// This borrows the sender's capability. A successful send is NOT an ACK
    /// and never authorizes release of the sender's original owner.
    pub fn send(
        &self,
        bytes: &[u8],
        descriptor: Option<&File>,
        deadline: Instant,
    ) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > IMAGE_CUSTODY_PACKET_BOUND {
            return Err(invalid("image custody packet length exceeds bound"));
        }
        loop {
            self.ready(libc::POLLOUT, deadline)?;
            let mut vector = libc::iovec {
                iov_base: bytes.as_ptr().cast_mut().cast(),
                iov_len: bytes.len(),
            };
            // SAFETY: initialized header subsequently points only to live bounded buffers.
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut vector;
            message.msg_iovlen = 1;
            let mut control = [0usize; 8];
            if let Some(file) = descriptor {
                // SAFETY: libc computes fixed ancillary storage lengths.
                let space = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;
                if space > size_of_val(&control) {
                    return Err(invalid("image custody send ancillary bound differs"));
                }
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen = space;
                // SAFETY: aligned control buffer covers a complete single-FD header.
                let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
                if header.is_null() {
                    return Err(invalid("image custody send header absent"));
                }
                // SAFETY: write one complete borrowed descriptor into admitted aligned storage.
                unsafe {
                    (*header).cmsg_level = libc::SOL_SOCKET;
                    (*header).cmsg_type = libc::SCM_RIGHTS;
                    (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;
                    libc::CMSG_DATA(header)
                        .cast::<libc::c_int>()
                        .write_unaligned(file.as_raw_fd());
                }
            }
            cutoff(deadline)?;
            // SAFETY: bounded live packet/control buffers; never block or signal SIGPIPE.
            let sent = unsafe {
                libc::sendmsg(
                    self.socket.as_raw_fd(),
                    &message,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if sent < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(error);
            }
            // Seqpacket preserves one whole message; never resend a partial commit.
            if sent as usize != bytes.len() {
                return Err(invalid("image custody packet send incomplete"));
            }
            return cutoff(deadline);
        }
    }

    pub fn receive(
        &self,
        expected: ImageCustodyPeer,
        deadline: Instant,
    ) -> io::Result<ImageCustodyPacket> {
        loop {
            self.ready(libc::POLLIN, deadline)?;
            let mut bytes = vec![0u8; IMAGE_CUSTODY_PACKET_BOUND];
            // Accommodate rejected extras so every delivered FD is adopted before rejection.
            // SAFETY: fixed finite counts, no pointer dereferences.
            let control_bytes = unsafe {
                libc::CMSG_SPACE((REJECT_DESCRIPTOR_BOUND * size_of::<libc::c_int>()) as u32)
                    + libc::CMSG_SPACE(size_of::<libc::ucred>() as u32)
            } as usize;
            let mut control = vec![0usize; control_bytes.div_ceil(size_of::<usize>())];
            let mut vector = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            // SAFETY: initialized header, subsequently assigned live bounded buffers.
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut vector;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = control_bytes;
            cutoff(deadline)?;
            // SAFETY: kernel writes only bounded packet/control buffers; received FDs CLOEXEC.
            let count = unsafe {
                libc::recvmsg(
                    self.socket.as_raw_fd(),
                    &mut message,
                    libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(error);
            }
            let mut received = Vec::<OwnedFd>::with_capacity(REJECT_DESCRIPTOR_BOUND);
            let mut credentials = None;
            let mut invalid_control = message.msg_controllen > control_bytes;
            if !invalid_control {
                // SAFETY: ancillary traversal is restricted to the returned bounded storage.
                let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
                let start = control.as_ptr() as usize;
                let end = start + message.msg_controllen;
                while !header.is_null() {
                    let address = header as usize;
                    // SAFETY: fixed libc ancillary header size, no pointer dereference.
                    let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
                    if address < start
                        || address
                            .checked_add(size_of::<libc::cmsghdr>())
                            .is_none_or(|n| n > end)
                    {
                        invalid_control = true;
                        break;
                    }
                    // SAFETY: fixed aligned header admitted in the kernel-returned extent.
                    let item = unsafe { &*header };
                    if item.cmsg_len < minimum
                        || address.checked_add(item.cmsg_len).is_none_or(|n| n > end)
                    {
                        invalid_control = true;
                        break;
                    }
                    let length = item.cmsg_len - minimum;
                    if item.cmsg_level == libc::SOL_SOCKET && item.cmsg_type == libc::SCM_RIGHTS {
                        if length % size_of::<libc::c_int>() != 0 {
                            invalid_control = true;
                        }
                        // SAFETY: complete descriptor integers lie within the admitted header.
                        let data = unsafe { libc::CMSG_DATA(header) }.cast::<libc::c_int>();
                        for ordinal in 0..length / size_of::<libc::c_int>() {
                            // SAFETY: each integer was supplied and installed by the kernel.
                            let raw = unsafe { data.add(ordinal).read_unaligned() };
                            if raw < 0 {
                                invalid_control = true;
                            } else {
                                // SAFETY: adopt EVERY received descriptor before any rejection.
                                let owner = unsafe { OwnedFd::from_raw_fd(raw) };
                                if received.len() < REJECT_DESCRIPTOR_BOUND {
                                    received.push(owner);
                                } else {
                                    invalid_control = true;
                                    drop(owner);
                                }
                            }
                        }
                    } else if item.cmsg_level == libc::SOL_SOCKET
                        && item.cmsg_type == libc::SCM_CREDENTIALS
                    {
                        if length != size_of::<libc::ucred>() || credentials.is_some() {
                            invalid_control = true;
                        } else {
                            // SAFETY: exact complete kernel credential record was admitted.
                            let value = unsafe {
                                libc::CMSG_DATA(header)
                                    .cast::<libc::ucred>()
                                    .read_unaligned()
                            };
                            credentials =
                                u32::try_from(value.pid).ok().map(|pid| ImageCustodyPeer {
                                    pid,
                                    uid: value.uid,
                                    gid: value.gid,
                                });
                        }
                    } else {
                        invalid_control = true;
                    }
                    // SAFETY: libc traversal advances within the same kernel-returned storage.
                    header = unsafe { libc::CMSG_NXTHDR(&message, header) };
                }
            }
            if invalid_control
                || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
                || count <= 0
                || count as usize > IMAGE_CUSTODY_PACKET_BOUND
                || received.len() > 1
                || expected.pid == 0
                || credentials != Some(expected)
            {
                // Every adopted extra or truncated-message descriptor drops here on error.
                return Err(invalid(
                    "image custody packet, descriptors or kernel credentials differ",
                ));
            }
            cutoff(deadline)?;
            bytes.truncate(count as usize);
            return Ok(ImageCustodyPacket {
                bytes,
                descriptor: received.pop().map(File::from),
            });
        }
    }
}

pub fn image_custody_current_peer() -> io::Result<ImageCustodyPeer> {
    Ok(ImageCustodyPeer::current())
}

pub fn image_custody_parent_pid() -> io::Result<u32> {
    // SAFETY: read-only kernel parent identity observation.
    let pid = unsafe { libc::getppid() };
    u32::try_from(pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| invalid("image custody parent PID is invalid"))
}

pub fn image_custody_monotonic_nanos() -> io::Result<u64> {
    // SAFETY: initialized writable timespec output for a read-only clock query.
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: native monotonic clock shared by these same-host processes.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(value.tv_sec).map_err(io::Error::other)?;
    let nanos = u64::try_from(value.tv_nsec).map_err(io::Error::other)?;
    if nanos >= 1_000_000_000 {
        return Err(invalid("image custody monotonic clock extent differs"));
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(nanos))
        .ok_or_else(|| invalid("image custody monotonic clock overflows"))
}

/// Clock order intentionally underestimates the original remaining allowance.
pub fn image_custody_cutoff_nanos(deadline: Instant) -> io::Result<u64> {
    let native_before = image_custody_monotonic_nanos()?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "image custody original cutoff elapsed",
            )
        })?;
    let remaining = u64::try_from(remaining.as_nanos()).map_err(io::Error::other)?;
    native_before
        .checked_add(remaining)
        .ok_or_else(|| invalid("image custody cutoff overflows"))
}

/// Instant-before/native-after conversion never renews an inherited allowance.
pub fn image_custody_deadline(cutoff_nanos: u64) -> io::Result<Instant> {
    let before = Instant::now();
    let native_after = image_custody_monotonic_nanos()?;
    let remaining = cutoff_nanos.checked_sub(native_after).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "image custody inherited cutoff elapsed",
        )
    })?;
    let result = before
        .checked_add(std::time::Duration::from_nanos(remaining))
        .ok_or_else(|| invalid("image custody inherited deadline overflows"))?;
    cutoff(result)?;
    Ok(result)
}

#[derive(Debug, Clone, Copy)]
pub struct ImageCustodyFdBudget {
    pub soft_limit: u64,
    pub open_descriptors: usize,
}

/// Observation only, never changes a process limit. The directory iterator's
/// own transient descriptor is counted conservatively; callers must reserve
/// their known concurrent command/pipe/query/cleanup maxima independently.
pub fn image_custody_fd_budget() -> io::Result<ImageCustodyFdBudget> {
    // SAFETY: initialized writable rlimit output for this process only.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: read-only query, does not modify resource limits.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut open_descriptors = 0usize;
    for entry in std::fs::read_dir("/proc/self/fd")? {
        entry?;
        open_descriptors = open_descriptors
            .checked_add(1)
            .ok_or_else(|| invalid("image custody descriptor count overflow"))?;
    }
    Ok(ImageCustodyFdBudget {
        soft_limit: limit.rlim_cur,
        open_descriptors,
    })
}

#[cfg(test)]
#[path = "../../tests/private/linux_image_custody_transport.rs"]
mod native_tests;
