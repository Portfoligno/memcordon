//! Owned caller state and counted, run-bound SCM_RIGHTS transport.
use serde::{Deserialize, Serialize};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::sync::{OnceLock, mpsc};
use std::time::Instant;

const MAX_FDS: usize = 128;
const MAX_MANIFEST: usize = 4096;
// Darwin sockargs(MT_CONTROL) rejects an allocation larger than MCLBYTES
// (2048 on both supported architectures). Reserve the entire kernel transport
// bound, independently of the 128-destination protocol limit: XNU externalizes
// rights before copyout_control truncates them, so undisclosed suffix rights
// cannot be reclaimed from a deliberately undersized receive buffer.
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_syscalls.c
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/i386/param.h
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/arm/param.h
const DARWIN_MAX_CONTROL_BYTES: usize = 2048;
type CaptureRequest = (
    crate::signal::CallerSignalSnapshot,
    Instant,
    mpsc::SyncSender<io::Result<Envelope>>,
);
static CAPTURE: OnceLock<Result<mpsc::SyncSender<CaptureRequest>, String>> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    mask: libc::sigset_t,
    ignored: Vec<i32>,
    limits: Vec<(i32, u64, u64)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    run: u64,
    destinations: Vec<i32>,
    settings: Settings,
}

pub(crate) struct Envelope {
    descriptors: Vec<(RawFd, OwnedFd)>,
    cwd: OwnedFd,
    pub(crate) settings: Settings,
}

fn error() -> io::Error {
    io::Error::other("invalid caller descriptor envelope")
}

pub(crate) fn duplicate(fd: RawFd, floor: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl creates an independent owned descriptor, without changing source flags.
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, floor) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

/// Adopt only complete descriptor words actually returned by recvmsg. Darwin
/// may retain the original cmsg_len after truncating the copied control bytes.
///
/// SAFETY: each distinct nonnegative SCM_RIGHTS word within `returned` must be
/// a descriptor newly transferred to this process, with no other Rust owner.
/// Negative and repeated words are rejected; bytes outside the returned extent
/// are never interpreted as descriptors.
unsafe fn receive_rights(
    ancillary: &[usize],
    returned: usize,
    flags: libc::c_int,
) -> io::Result<Vec<OwnedFd>> {
    let capacity = std::mem::size_of_val(ancillary);
    let extent = returned.min(capacity);
    let mut invalid = returned > capacity || flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0;
    let mut rights = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut offset = 0usize;
    let header_length = unsafe { libc::CMSG_LEN(0) } as usize;
    while offset < extent {
        if extent - offset < std::mem::size_of::<libc::cmsghdr>() {
            invalid = true;
            break;
        }
        // SAFETY: the complete header is inside the returned and allocated extent.
        let header = unsafe {
            std::ptr::read_unaligned(
                ancillary
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<libc::cmsghdr>(),
            )
        };
        let length = header.cmsg_len as usize;
        if length < header_length {
            invalid = true;
            break;
        }
        let available = extent - offset;
        invalid |= length > available;
        let payload_length = length - header_length;
        let copied_payload = length.min(available).saturating_sub(header_length);
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            invalid |= payload_length % std::mem::size_of::<RawFd>() != 0
                || copied_payload % std::mem::size_of::<RawFd>() != 0;
            for index in 0..copied_payload / std::mem::size_of::<RawFd>() {
                let word = offset + header_length + index * std::mem::size_of::<RawFd>();
                // SAFETY: only full words inside the returned extent are read.
                let fd = unsafe {
                    std::ptr::read_unaligned(
                        ancillary.as_ptr().cast::<u8>().add(word).cast::<RawFd>(),
                    )
                };
                if fd < 0 || !seen.insert(fd) {
                    invalid = true;
                    continue;
                }
                // SAFETY: caller transfers ownership of the returned SCM_RIGHTS
                // descriptors. Duplicate words are never adopted a second time.
                rights.push(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        } else {
            invalid = true;
        }
        if length > available {
            break;
        }
        let advance = unsafe { libc::CMSG_SPACE(payload_length as u32) } as usize;
        if advance > available {
            break;
        }
        offset += advance;
    }
    if invalid { Err(error()) } else { Ok(rights) }
}

fn receive_packet(socket: &UnixDatagram) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut payload = [0u8; MAX_MANIFEST];
    let space = DARWIN_MAX_CONTROL_BYTES;
    let mut ancillary = vec![0usize; space.div_ceil(std::mem::size_of::<usize>())];
    let mut vector = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = space as _;
    let count = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: recvmsg installs independent owned descriptors in the returned
    // SCM_RIGHTS extent. The parser bounds every header and word by both
    // msg_controllen and this allocation before adopting it.
    let rights = unsafe {
        receive_rights(
            &ancillary,
            message.msg_controllen as usize,
            message.msg_flags,
        )?
    };
    let count = usize::try_from(count).map_err(|_| error())?;
    let payload = payload.get(..count).ok_or_else(error)?.to_vec();
    Ok((payload, rights))
}

impl Envelope {
    pub(crate) fn capture_bounded(
        deadline: Instant,
        snapshot: crate::signal::CallerSignalSnapshot,
        admission: Option<&crate::signal::LaunchAdmission>,
    ) -> io::Result<Self> {
        let expires = crate::macos_deadline::add(
            crate::macos_deadline::continuous_nanos()?,
            deadline.saturating_duration_since(Instant::now()),
        )?;
        // The mask is thread-local and must be sampled on the invoking thread.
        // Filesystem/descriptor enumeration remains owned by the single capture
        // worker; timing out does not submit another unbounded replacement.
        let worker = CAPTURE
            .get_or_init(|| {
                let (sender, receiver) = mpsc::sync_channel::<CaptureRequest>(0);
                std::thread::Builder::new()
                    .name("memcordon-caller-envelope".into())
                    .spawn(move || {
                        while let Ok((snapshot, deadline, sender)) = receiver.recv() {
                            let result = if Instant::now() >= deadline {
                                Err(io::Error::new(
                                    io::ErrorKind::TimedOut,
                                    "caller capture admission expired",
                                ))
                            } else {
                                Self::capture_with_snapshot(snapshot)
                            };
                            let _ = sender.send(result);
                        }
                    })
                    .map_err(|error| error.to_string())?;
                Ok(sender)
            })
            .as_ref()
            .map_err(|message| io::Error::other(message.clone()))?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut request = (snapshot, deadline, sender);
        loop {
            if let Some(admission) = admission {
                admission.check()?;
            }
            match worker.try_send(request) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Full(returned)) => request = returned,
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err(io::Error::other("caller capture owner unavailable"));
                }
            }
            if crate::macos_deadline::continuous_nanos()? >= expires {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "caller capture slot remains occupied",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        loop {
            if let Some(admission) = admission {
                admission.check()?;
            }
            if crate::macos_deadline::continuous_nanos()? >= expires {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "caller capture remains owned in flight",
                ));
            }
            match receiver.recv_timeout(std::time::Duration::from_millis(2)) {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("caller capture owner unavailable"));
                }
            }
        }
    }
    pub(crate) fn private_floor(&self) -> io::Result<RawFd> {
        self.descriptors
            .iter()
            .map(|(destination, _)| *destination)
            .max()
            .unwrap_or(2)
            .checked_add(1)
            .ok_or_else(error)
    }
    #[cfg(feature = "test-support")]
    pub(crate) fn capture() -> io::Result<Self> {
        Self::capture_with_snapshot(crate::signal::CallerSignalSnapshot::capture()?)
    }

    fn capture_with_snapshot(snapshot: crate::signal::CallerSignalSnapshot) -> io::Result<Self> {
        let limit = unsafe { libc::getdtablesize() };
        if !(3..=1_048_576).contains(&limit) {
            return Err(error());
        }
        let mut descriptors = Vec::new();
        for fd in 0..limit {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 {
                if io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
                    return Err(io::Error::last_os_error());
                }
                continue;
            }
            if flags & libc::FD_CLOEXEC == 0 {
                if descriptors.len() == MAX_FDS {
                    return Err(error());
                }
                descriptors.push((fd, duplicate(fd, 3)?));
            }
        }
        let cwd = unsafe {
            libc::open(
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if cwd < 0 {
            return Err(io::Error::last_os_error());
        }
        let cwd = unsafe { OwnedFd::from_raw_fd(cwd) };
        let mut limits = Vec::new();
        for resource in [
            libc::RLIMIT_CPU,
            libc::RLIMIT_FSIZE,
            libc::RLIMIT_DATA,
            libc::RLIMIT_STACK,
            libc::RLIMIT_CORE,
            libc::RLIMIT_RSS,
            libc::RLIMIT_MEMLOCK,
            libc::RLIMIT_NPROC,
            libc::RLIMIT_NOFILE,
        ] {
            let mut value = std::mem::MaybeUninit::<libc::rlimit>::uninit();
            if unsafe { libc::getrlimit(resource, value.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let value = unsafe { value.assume_init() };
            limits.push((resource, value.rlim_cur, value.rlim_max));
        }
        Ok(Self {
            descriptors,
            cwd,
            settings: Settings {
                mask: snapshot.mask,
                ignored: snapshot.ignored,
                limits,
            },
        })
    }

    pub(crate) fn send(&self, socket: &UnixDatagram, run: u64) -> io::Result<()> {
        let payload = serde_json::to_vec(&Manifest {
            version: 1,
            run,
            destinations: self.descriptors.iter().map(|(fd, _)| *fd).collect(),
            settings: self.settings.clone(),
        })?;
        if payload.len() > MAX_MANIFEST {
            return Err(error());
        }
        let rights = self
            .descriptors
            .iter()
            .map(|(_, fd)| fd.as_raw_fd())
            .chain(std::iter::once(self.cwd.as_raw_fd()))
            .collect::<Vec<_>>();
        let rights_size = std::mem::size_of_val(rights.as_slice());
        let space =
            unsafe { libc::CMSG_SPACE(u32::try_from(rights_size).map_err(|_| error())?) } as usize;
        let mut ancillary = vec![0usize; space.div_ceil(std::mem::size_of::<usize>())];
        let mut vector = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = space as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(rights_size as u32);
            std::ptr::copy_nonoverlapping(
                rights.as_ptr(),
                libc::CMSG_DATA(header).cast::<RawFd>(),
                rights.len(),
            );
            let count = libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_DONTWAIT);
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            if usize::try_from(count).ok() != Some(payload.len()) {
                return Err(error());
            }
        }
        Ok(())
    }

    pub(crate) fn receive(socket: &UnixDatagram, run: u64, floor: RawFd) -> io::Result<Self> {
        let (payload, rights) = receive_packet(socket)?;
        let manifest: Manifest = serde_json::from_slice(&payload)?;
        if manifest.version != 1
            || manifest.run != run
            || manifest.destinations.len() > MAX_FDS
            || rights.len() != manifest.destinations.len() + 1
        {
            return Err(error());
        }
        let mut destinations = manifest.destinations.clone();
        destinations.sort_unstable();
        if destinations.iter().any(|fd| *fd < 0)
            || destinations.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(error());
        }
        let floor = floor.max(
            destinations
                .last()
                .copied()
                .unwrap_or(2)
                .checked_add(1)
                .ok_or_else(error)?,
        );
        let mut promoted = rights
            .iter()
            .map(|fd| duplicate(fd.as_raw_fd(), floor))
            .collect::<io::Result<Vec<_>>>()?;
        let cwd = promoted.pop().ok_or_else(error)?;
        Ok(Self {
            descriptors: manifest.destinations.into_iter().zip(promoted).collect(),
            cwd,
            settings: manifest.settings,
        })
    }

    /// Called only while constructing actions in the reserved native spawn owner.
    pub(crate) unsafe fn actions(
        &self,
        actions: &mut libc::posix_spawn_file_actions_t,
        attributes: &mut libc::posix_spawnattr_t,
        target: bool,
    ) -> io::Result<()> {
        unsafe extern "C" {
            fn posix_spawn_file_actions_addfchdir_np(
                actions: *mut libc::posix_spawn_file_actions_t,
                fd: i32,
            ) -> i32;
        }
        check(unsafe { posix_spawn_file_actions_addfchdir_np(actions, self.cwd.as_raw_fd()) })?;
        check(unsafe { libc::posix_spawn_file_actions_addclose(actions, self.cwd.as_raw_fd()) })?;
        check(unsafe { libc::posix_spawnattr_setsigmask(attributes, &self.settings.mask) })?;
        if target {
            for (destination, source) in &self.descriptors {
                check(unsafe {
                    libc::posix_spawn_file_actions_adddup2(
                        actions,
                        source.as_raw_fd(),
                        *destination,
                    )
                })?;
                check(unsafe {
                    libc::posix_spawn_file_actions_addclose(actions, source.as_raw_fd())
                })?;
            }
            for fd in [0, 1, 2] {
                if !self
                    .descriptors
                    .iter()
                    .any(|(destination, _)| *destination == fd)
                {
                    check(unsafe { libc::posix_spawn_file_actions_addclose(actions, fd) })?;
                }
            }
        }
        Ok(())
    }
}

/// Independently construct a bounded SCM_RIGHTS packet for native receiver
/// characterization. No caller signal, limit, descriptor, or cwd is changed.
#[cfg(feature = "test-support")]
pub fn receive_manifest_fixture(
    payload: &[u8],
    run: u64,
    rights_count: usize,
) -> io::Result<Vec<u8>> {
    if payload.len() > MAX_MANIFEST + 1 || rights_count > MAX_FDS + 2 {
        return Err(error());
    }
    let directory = std::fs::File::open(".")?;
    let rights = vec![directory.as_raw_fd(); rights_count];
    let receiver = send_packet_fixture(payload, &rights)?;
    let envelope = Envelope::receive(&receiver, run, 3)?;
    Ok(serde_json::to_vec(&Manifest {
        version: 1,
        run,
        destinations: envelope
            .descriptors
            .iter()
            .map(|(destination, _)| *destination)
            .collect(),
        settings: envelope.settings,
    })?)
}

#[cfg(feature = "test-support")]
fn send_packet_fixture(payload: &[u8], rights: &[RawFd]) -> io::Result<UnixDatagram> {
    let (sender, receiver) = UnixDatagram::pair()?;
    if rights.is_empty() {
        sender.send(payload)?;
    } else {
        let size = u32::try_from(std::mem::size_of_val(rights)).map_err(|_| error())?;
        // SAFETY: the aligned storage is sized for exactly the typed fd array;
        // all descriptors remain owned until sendmsg completes.
        let space = unsafe { libc::CMSG_SPACE(size) } as usize;
        let mut ancillary = vec![0usize; space.div_ceil(std::mem::size_of::<usize>())];
        let mut vector = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = space as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size);
            std::ptr::copy_nonoverlapping(
                rights.as_ptr(),
                libc::CMSG_DATA(header).cast::<RawFd>(),
                rights.len(),
            );
            let sent = libc::sendmsg(sender.as_raw_fd(), &message, libc::MSG_DONTWAIT);
            if sent < 0 {
                return Err(io::Error::last_os_error());
            }
            if usize::try_from(sent).ok() != Some(payload.len()) {
                return Err(error());
            }
        }
    }
    Ok(receiver)
}

#[cfg(feature = "test-support")]
#[path = "../tests/support/macos_ancillary_custody.rs"]
mod custody_fixture;
#[cfg(feature = "test-support")]
pub use custody_fixture::ancillary_custody_fixture;

fn check(status: i32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

/// Runs only in the disposable native fixture process; cwd mutation is intentional.
#[cfg(feature = "test-support")]
pub fn transfer_fixture(directory: &std::path::Path) -> io::Result<()> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let original = directory.join("original");
    let replacement = directory.join("replacement");
    std::fs::create_dir(&original)?;
    std::fs::create_dir(&replacement)?;
    let source_path = original.join("source");
    let replacement_path = replacement.join("source");
    std::fs::write(&source_path, b"captured source\n")?;
    std::fs::write(&replacement_path, b"reused descriptor\n")?;
    let source = std::fs::File::open(source_path)?;
    let source_fd = source.as_raw_fd();
    if unsafe { libc::fcntl(source_fd, libc::F_SETFD, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    std::env::set_current_dir(&original)?;
    let captured = Envelope::capture()?;
    let source_flags = unsafe { libc::fcntl(source_fd, libc::F_GETFL) };
    drop(source);
    let replacement_file = std::fs::File::open(replacement_path)?;
    if unsafe { libc::dup2(replacement_file.as_raw_fd(), source_fd) } < 0 {
        return Err(io::Error::last_os_error());
    }
    std::env::set_current_dir(&replacement)?;
    let (send, receive) = UnixDatagram::pair()?;
    captured.send(&send, 71)?;
    let transferred = Envelope::receive(&receive, 71, captured.private_floor()?)?;
    let descriptor = transferred
        .descriptors
        .iter()
        .find(|(destination, _)| *destination == source_fd)
        .ok_or_else(error)?;
    if unsafe { libc::fcntl(descriptor.1.as_raw_fd(), libc::F_GETFL) } != source_flags {
        return Err(io::Error::other("capture changed shared descriptor flags"));
    }
    let mut file = std::fs::File::from(duplicate(descriptor.1.as_raw_fd(), 3)?);
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    if contents != b"captured source\n" {
        return Err(io::Error::other("descriptor reuse changed captured source"));
    }
    let cwd = std::fs::File::from(duplicate(transferred.cwd.as_raw_fd(), 3)?).metadata()?;
    let expected = std::fs::metadata(original)?;
    if (cwd.dev(), cwd.ino()) != (expected.dev(), expected.ino()) {
        return Err(io::Error::other("cwd change altered captured directory"));
    }
    captured.send(&send, 71)?;
    if Envelope::receive(&receive, 72, 3).is_ok() {
        return Err(io::Error::other("wrong-run manifest accepted"));
    }
    let manifest = Manifest {
        version: 1,
        run: 71,
        destinations: vec![source_fd],
        settings: captured.settings.clone(),
    };
    send.send(&serde_json::to_vec(&manifest)?)?;
    if Envelope::receive(&receive, 71, 3).is_ok() {
        return Err(io::Error::other("missing descriptor rights accepted"));
    }
    Ok(())
}

impl Settings {
    pub(crate) fn restore(&self) -> io::Result<()> {
        if self.ignored.windows(2).any(|pair| pair[0] >= pair[1])
            || self.ignored.iter().any(|signal| {
                !(1..=libc::SIGUSR2).contains(signal)
                    || [libc::SIGKILL, libc::SIGSTOP].contains(signal)
            })
        {
            return Err(error());
        }
        for signal in 1..=libc::SIGUSR2 {
            if [libc::SIGKILL, libc::SIGSTOP].contains(&signal) {
                continue;
            }
            if unsafe {
                libc::signal(
                    signal,
                    if self.ignored.contains(&signal) {
                        libc::SIG_IGN
                    } else {
                        libc::SIG_DFL
                    },
                )
            } == libc::SIG_ERR
            {
                return Err(io::Error::last_os_error());
            }
        }
        for (resource, current, maximum) in &self.limits {
            let value = libc::rlimit {
                rlim_cur: *current,
                rlim_max: *maximum,
            };
            if unsafe { libc::setrlimit(*resource, &value) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}
