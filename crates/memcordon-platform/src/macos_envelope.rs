//! Owned caller state and counted, run-bound SCM_RIGHTS transport.
use serde::{Deserialize, Serialize};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::sync::{OnceLock, mpsc};
use std::time::Instant;

const MAX_FDS: usize = 128;
const MAX_MANIFEST: usize = 4096;
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
        let mut payload = [0u8; MAX_MANIFEST];
        let space =
            unsafe { libc::CMSG_SPACE(((MAX_FDS + 1) * std::mem::size_of::<RawFd>()) as u32) }
                as usize;
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
        let mut rights = Vec::new();
        let mut invalid = message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0;
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&message);
            while !header.is_null() {
                if (*header).cmsg_level != libc::SOL_SOCKET
                    || (*header).cmsg_type != libc::SCM_RIGHTS
                {
                    invalid = true;
                    break;
                }
                let bytes = ((*header).cmsg_len as usize)
                    .checked_sub(libc::CMSG_LEN(0) as usize)
                    .ok_or_else(error)?;
                if bytes % std::mem::size_of::<RawFd>() != 0 {
                    invalid = true;
                    break;
                }
                for index in 0..bytes / std::mem::size_of::<RawFd>() {
                    rights.push(OwnedFd::from_raw_fd(
                        *libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                    ));
                }
                header = libc::CMSG_NXTHDR(&message, header);
            }
        }
        if invalid {
            return Err(error());
        }
        let manifest: Manifest =
            serde_json::from_slice(&payload[..usize::try_from(count).map_err(|_| error())?])?;
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
