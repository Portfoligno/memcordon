//! Native permission and syscall stops for current controller experiments.
//! Handles enter this module only from the kernel or an original live query hold.
#![allow(unsafe_code)]
use crate::{CiError, Result};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

/// Map one original retained source descriptor into the original frontend.
/// Occupied slots are refused, including any native spawn error channel.
pub(crate) fn configure_extra_descriptor(
    command: &mut std::process::Command,
    source: &File,
) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    let held = rustix::io::fcntl_dupfd_cloexec(source, 129).map_err(std::io::Error::from)?;
    // SAFETY: the child callback uses only async-signal-safe fcntl/dup2 and
    // reads its already owned descriptor. No parent descriptor is modified.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(128, libc::F_GETFD) >= 0 {
                return Err(std::io::Error::from_raw_os_error(libc::EEXIST));
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBADF) {
                return Err(error);
            }
            if libc::dup2(held.as_raw_fd(), 128) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

pub struct PermissionStop {
    group: Arc<File>,
    file: File,
    pub process_id: u32,
    pub record: Vec<u8>,
    pub device: u64,
    pub inode: u64,
    pub directory_device: u64,
    pub directory_inode: u64,
    released: bool,
    release_errno: Option<i32>,
    scope_is_directory: bool,
    file_uid: u32,
    file_length: u64,
}
impl PermissionStop {
    pub fn allow(&mut self) -> Result<()> {
        if self.released {
            return Ok(());
        }
        let mut response = Vec::with_capacity(8);
        response.extend(self.file.as_raw_fd().to_ne_bytes());
        response.extend((libc::FAN_ALLOW as u32).to_ne_bytes());
        let mut group = &*self.group;
        if let Err(error) = group.write_all(&response) {
            self.release_errno = error.raw_os_error();
            return Err(error.into());
        }
        self.released = true;
        Ok(())
    }
    pub fn observation(&self) -> serde_json::Value {
        serde_json::json!({"mechanism":"fanotify-open-permission","pid":self.process_id,"device":self.device,"inode":self.inode,"directory_device":self.directory_device,"directory_inode":self.directory_inode,"scope_kind":if self.scope_is_directory{"directory"}else{"file"},"file_uid":self.file_uid,"file_length":self.file_length,"record_read":self.scope_is_directory,"record_sha256":super::artifacts::checksum(&self.record),"allow_written":self.released,"allow_errno":self.release_errno})
    }
}
impl Drop for PermissionStop {
    fn drop(&mut self) {
        let _ = self.allow();
    }
}

pub struct NativeReadGate {
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    events: mpsc::Receiver<Result<PermissionStop>>,
    cutoff: Instant,
}
impl NativeReadGate {
    pub fn new(
        directory: &Path,
        cutoff: Instant,
        predicate: impl Fn(u32, &[u8]) -> bool + Send + 'static,
    ) -> Result<Self> {
        if Instant::now() >= cutoff {
            return Err(CiError::Message(
                "original native phase gate cutoff exhausted".into(),
            ));
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory)?;
        let identity = root.metadata()?;
        if !identity.is_dir() || identity.uid() != 0 || identity.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "native phase gate directory has unprotected custody".into(),
            ));
        }
        Self::start(root, true, cutoff, predicate)
    }

    pub fn on_file(file: &File, caller_uid: u32, cutoff: Instant) -> Result<Self> {
        let identity = file.metadata()?;
        let flags = rustix::fs::fcntl_getfl(file).map_err(std::io::Error::from)?;
        if !identity.is_file()
            || identity.uid() != caller_uid
            || caller_uid == 0
            || identity.nlink() != 1
            || identity.len() == 0
            || flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
        {
            return Err(CiError::Message(
                "caller input gate lacks the original readonly named file custody".into(),
            ));
        }
        Self::start(file.try_clone()?, false, cutoff, |_, _| true)
    }

    pub fn on_current_executable(file: &File, cutoff: Instant) -> Result<Self> {
        let identity = file.metadata()?;
        let flags = rustix::fs::fcntl_getfl(file).map_err(std::io::Error::from)?;
        if !identity.is_file()
            || identity.uid() != 0
            || identity.mode() & 0o777 != 0o555
            || identity.nlink() != 1
            || identity.len() == 0
            || flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
        {
            return Err(CiError::Message(
                "current package gate lacks its exact protected readonly executable".into(),
            ));
        }
        let expected = (identity.dev(), identity.ino());
        Self::start(file.try_clone()?, false, cutoff, move |pid, _| {
            // Ignore the pre-exec open so Command can complete its exec
            // handshake; select the running agent's later source read.
            std::fs::metadata(format!("/proc/{pid}/exe"))
                .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == expected)
        })
    }

    fn start(
        root: File,
        scope_is_directory: bool,
        cutoff: Instant,
        predicate: impl Fn(u32, &[u8]) -> bool + Send + 'static,
    ) -> Result<Self> {
        if Instant::now() >= cutoff {
            return Err(CiError::Message(
                "original native file gate cutoff exhausted".into(),
            ));
        }
        let identity = root.metadata()?;
        // SAFETY: this creates a new kernel-owned descriptor with fixed flags.
        let raw = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
                (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_LARGEFILE) as u32,
            )
        };
        if raw < 0 {
            return Err(CiError::Message(format!(
                "native fanotify phase gate unavailable: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: fanotify_init returned this fresh, uniquely owned descriptor.
        let group = Arc::new(unsafe { File::from_raw_fd(raw) });
        let path = std::ffi::CString::new(format!("/proc/self/fd/{}", root.as_raw_fd()))
            .expect("numeric held descriptor path");
        // SAFETY: the live directory FD pins the kernel path and CString lifetime.
        let marked = unsafe {
            libc::fanotify_mark(
                group.as_raw_fd(),
                libc::FAN_MARK_ADD
                    | if scope_is_directory {
                        libc::FAN_MARK_ONLYDIR
                    } else {
                        0
                    },
                libc::FAN_OPEN_PERM
                    | if scope_is_directory {
                        libc::FAN_EVENT_ON_CHILD
                    } else {
                        0
                    },
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };
        if marked < 0 {
            return Err(CiError::Message(format!(
                "native fanotify mark unavailable: {}",
                std::io::Error::last_os_error()
            )));
        }
        let stopped = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stopped);
        let (send, events) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("current-native-phase".into())
            .spawn(move || {
                let _directory = root;
                let run = (|| -> Result<()> {
                    let mut bytes = [0u8; 65536];
                    let mut selected = false;
                    while !worker_stop.load(Ordering::Acquire) && Instant::now() < cutoff {
                        let mut source = &*group;
                        let count = match source.read(&mut bytes) {
                            Ok(0) => {
                                return Err(CiError::Message(
                                    "native phase event group closed".into(),
                                ));
                            }
                            Ok(count) => count,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(1));
                                continue;
                            }
                            Err(error) => return Err(error.into()),
                        };
                        let mut offset = 0;
                        while offset < count {
                            if count - offset < std::mem::size_of::<libc::fanotify_event_metadata>()
                            {
                                return Err(CiError::Message(
                                    "native fanotify event truncated".into(),
                                ));
                            }
                            // SAFETY: the kernel supplied a complete fixed metadata prefix;
                            // unaligned access is used and all extents are checked below.
                            let event = unsafe {
                                std::ptr::read_unaligned(
                                    bytes[offset..]
                                        .as_ptr()
                                        .cast::<libc::fanotify_event_metadata>(),
                                )
                            };
                            let length = event.event_len as usize;
                            if length < std::mem::size_of::<libc::fanotify_event_metadata>()
                                || length > count - offset
                                || event.vers != libc::FANOTIFY_METADATA_VERSION
                            {
                                return Err(CiError::Message(
                                    "native fanotify event version/extent differs".into(),
                                ));
                            }
                            offset += length;
                            if event.fd < 0 {
                                return Err(CiError::Message(
                                    "native fanotify event overflow or missing FD".into(),
                                ));
                            }
                            // SAFETY: this event transfers exactly one fresh kernel FD.
                            let mut file = unsafe { File::from_raw_fd(event.fd) };
                            let metadata = file.metadata()?;
                            let mut record = Vec::new();
                            let valid = if scope_is_directory {
                                metadata.is_file()
                                    && metadata.uid() == 0
                                    && metadata.nlink() == 1
                                    && metadata.mode() & 0o777 == 0o600
                                    && metadata.len() > 0
                                    && metadata.len() <= 512 * 1024
                            } else {
                                metadata.is_file()
                                    && metadata.uid() == identity.uid()
                                    && metadata.nlink() == 1
                                    && metadata.len() == identity.len()
                                    && (metadata.dev(), metadata.ino())
                                        == (identity.dev(), identity.ino())
                            };
                            if valid && scope_is_directory {
                                (&mut file).take(512 * 1024 + 1).read_to_end(&mut record)?;
                            }
                            let pid = u32::try_from(event.pid).map_err(|_| {
                                CiError::Message("native fanotify process identity invalid".into())
                            })?;
                            let mut permission = PermissionStop {
                                group: Arc::clone(&group),
                                file,
                                process_id: pid,
                                record,
                                device: metadata.dev(),
                                inode: metadata.ino(),
                                directory_device: if scope_is_directory {
                                    identity.dev()
                                } else {
                                    0
                                },
                                directory_inode: if scope_is_directory {
                                    identity.ino()
                                } else {
                                    0
                                },
                                released: false,
                                release_errno: None,
                                scope_is_directory,
                                file_uid: metadata.uid(),
                                file_length: metadata.len(),
                            };
                            if !selected
                                && valid
                                && event.mask & libc::FAN_OPEN_PERM != 0
                                && pid != std::process::id()
                                && predicate(pid, &permission.record)
                            {
                                selected = true;
                                if send.send(Ok(permission)).is_err() {
                                    return Ok(());
                                }
                            } else {
                                permission.allow()?;
                            }
                        }
                    }
                    Ok(())
                })();
                if let Err(error) = run {
                    let _ = send.send(Err(error));
                }
            })?;
        Ok(Self {
            stopped,
            worker: Some(worker),
            events,
            cutoff,
        })
    }
    pub fn wait(&self) -> Result<PermissionStop> {
        self.wait_for_inner(None)
    }
    pub fn wait_for(
        &self,
        process: &crate::linux_consumer_readiness::HeldLinuxProcess,
    ) -> Result<PermissionStop> {
        self.wait_for_inner(Some(process))
    }
    fn wait_for_inner(
        &self,
        process: Option<&crate::linux_consumer_readiness::HeldLinuxProcess>,
    ) -> Result<PermissionStop> {
        loop {
            let now = Instant::now();
            if now >= self.cutoff {
                return Err(CiError::Message(
                    "original native permission gate cutoff exhausted".into(),
                ));
            }
            match self
                .events
                .recv_timeout(Duration::from_millis(10).min(self.cutoff - now))
            {
                Ok(event) => return event,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(process) = process {
                        if process.exited().map_err(CiError::Message)? {
                            return Err(CiError::Message(
                                "original frontend retired before the required native phase event"
                                    .into(),
                            ));
                        }
                    }
                }
                Err(error) => {
                    return Err(CiError::Message(format!(
                        "native permission gate ended: {error}"
                    )));
                }
            }
        }
    }
}
impl Drop for NativeReadGate {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub struct NativeTraceStop {
    process: crate::linux_consumer_readiness::HeldLinuxProcess,
    cutoff: Instant,
    attached: bool,
    stopped: bool,
}
impl NativeTraceStop {
    pub fn attach(
        process: crate::linux_consumer_readiness::HeldLinuxProcess,
        permission: &mut PermissionStop,
        cutoff: Instant,
    ) -> Result<Self> {
        if process.process_id != permission.process_id
            || process.exited().map_err(CiError::Message)?
            || Instant::now() >= cutoff
        {
            return Err(CiError::Message(
                "syscall tracer does not hold the original live permission-event process".into(),
            ));
        }
        let mut trace = Self {
            process,
            cutoff,
            attached: false,
            stopped: false,
        };
        trace.control(
            libc::PTRACE_SEIZE,
            0,
            (libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_EXITKILL) as usize,
        )?;
        trace.attached = true;
        trace.control(libc::PTRACE_INTERRUPT, 0, 0)?;
        permission.allow()?;
        let status = trace.wait_stop()?;
        if !libc::WIFSTOPPED(status) || status >> 16 != libc::PTRACE_EVENT_STOP {
            return Err(CiError::Message(
                "original permission-event process did not enter its actual ptrace stop".into(),
            ));
        }
        Ok(trace)
    }
    fn control(&self, request: libc::c_uint, address: usize, data: usize) -> Result<libc::c_long> {
        let pid = i32::try_from(self.process.process_id)
            .map_err(|error| CiError::Message(error.to_string()))?;
        // SAFETY: pid belongs to the original live pidfd-held permission event.
        // All operations are fixed ptrace controls; the one output buffer is
        // bounded and owned by syscall_info for its complete call lifetime.
        let result = unsafe {
            libc::ptrace(
                request,
                pid,
                address as *mut libc::c_void,
                data as *mut libc::c_void,
            )
        };
        if result < 0 {
            return Err(CiError::Message(format!(
                "native ptrace operation {request} unavailable: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(result)
    }
    fn wait_stop(&mut self) -> Result<i32> {
        let pid = i32::try_from(self.process.process_id)
            .map_err(|error| CiError::Message(error.to_string()))?;
        while Instant::now() < self.cutoff {
            let mut status = 0;
            // SAFETY: PTRACE_SEIZE established this debugger relationship. This
            // wait observes debugger stops, not the frontend Child's sole wait.
            let observed = unsafe { libc::waitpid(pid, &mut status, libc::__WALL | libc::WNOHANG) };
            if observed == pid {
                self.stopped = libc::WIFSTOPPED(status);
                if !self.stopped {
                    self.attached = false;
                    return Err(CiError::Message(format!(
                        "original trace process retired before its selected boundary: {status}"
                    )));
                }
                return Ok(status);
            }
            if observed < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error.into());
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Err(CiError::Message(
            "original syscall phase gate cutoff exhausted".into(),
        ))
    }
    fn syscall_info(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; 128];
        let written = usize::try_from(self.control(
            libc::PTRACE_GET_SYSCALL_INFO,
            bytes.len(),
            bytes.as_mut_ptr() as usize,
        )?)
        .map_err(|error| CiError::Message(error.to_string()))?;
        if written > bytes.len() || written < 24 {
            return Err(CiError::Message(
                "native syscall observation length invalid".into(),
            ));
        }
        bytes.truncate(written);
        Ok(bytes)
    }
    fn next_syscall(&mut self) -> Result<Vec<u8>> {
        let mut signal = 0;
        loop {
            self.control(libc::PTRACE_SYSCALL, 0, signal)?;
            self.stopped = false;
            let status = self.wait_stop()?;
            if libc::WSTOPSIG(status) == libc::SIGTRAP | 0x80 {
                return self.syscall_info();
            }
            if status >> 16 != 0 {
                return Err(CiError::Message(
                    "unexpected native debugger event while seeking current transaction".into(),
                ));
            }
            signal = usize::try_from(libc::WSTOPSIG(status))
                .map_err(|error| CiError::Message(error.to_string()))?;
        }
    }
    fn pathname(&self, address: u64) -> Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        let memory = File::open(format!("/proc/{}/mem", self.process.process_id))?;
        let mut bytes = Vec::new();
        for offset in 0..256_u64 {
            if Instant::now() >= self.cutoff {
                return Err(CiError::Message(
                    "original syscall pathname cutoff exhausted".into(),
                ));
            }
            let mut byte = [0];
            if memory.read_at(
                &mut byte,
                address
                    .checked_add(offset)
                    .ok_or_else(|| CiError::Message("native pathname address overflow".into()))?,
            )? != 1
            {
                return Err(CiError::Message("native syscall pathname shortened".into()));
            }
            if byte[0] == 0 {
                return Ok(bytes);
            }
            bytes.push(byte[0]);
        }
        Err(CiError::Message(
            "native transaction pathname exceeds bound".into(),
        ))
    }
    /// Stop immediately after the selected successful native rename publishes
    /// the exact pending record. The worker has not resumed userspace cleanup.
    /// Stop the original traced process after a successful read from the held
    /// source inode, while its cursor is strictly inside the remaining bytes.
    pub fn after_source_read(
        &mut self,
        source: &File,
        minimum: u64,
        ready: impl Fn() -> bool,
    ) -> Result<serde_json::Value> {
        use std::os::unix::fs::MetadataExt;
        let original = source.metadata()?;
        if !original.is_file() || original.len() <= minimum {
            return Err(CiError::Message(
                "source read gate has no remaining original extent".into(),
            ));
        }
        for _ in 0..65536 {
            let entry = self.next_syscall()?;
            if entry.first() != Some(&1) || entry.len() < 80 {
                continue;
            }
            let architecture =
                u32::from_ne_bytes(entry[4..8].try_into().expect("bounded syscall info"));
            let number =
                u64::from_ne_bytes(entry[24..32].try_into().expect("bounded syscall info"));
            if !((architecture == 0xc000003e && number == 0)
                || (architecture == 0xc00000b7 && number == 63))
            {
                continue;
            }
            let descriptor =
                u64::from_ne_bytes(entry[32..40].try_into().expect("bounded source descriptor"));
            let path = format!("/proc/{}/fd/{descriptor}", self.process.process_id);
            let actual = match std::fs::metadata(&path) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if (actual.dev(), actual.ino()) != (original.dev(), original.ino()) {
                continue;
            }
            let exit = self.next_syscall()?;
            if exit.first() != Some(&2) || exit.len() < 33 || exit[32] != 0 {
                return Err(CiError::Message(
                    "original source read did not reach successful native exit".into(),
                ));
            }
            let count =
                i64::from_ne_bytes(exit[24..32].try_into().expect("bounded source read result"));
            if count <= 0 {
                continue;
            }
            let fdinfo = std::fs::read_to_string(format!(
                "/proc/{}/fdinfo/{descriptor}",
                self.process.process_id
            ))?;
            let positions = fdinfo
                .lines()
                .filter_map(|line| line.strip_prefix("pos:"))
                .collect::<Vec<_>>();
            if positions.len() != 1 {
                return Err(CiError::Message(
                    "original source cursor absent or duplicate".into(),
                ));
            }
            let position = positions[0]
                .trim()
                .parse::<u64>()
                .map_err(|error| CiError::Message(error.to_string()))?;
            if position > minimum && position < original.len() && ready() {
                return Ok(
                    serde_json::json!({"format":"memcordon.current-source-read-stop","revision":1,"process":{"pid":self.process.process_id,"birth":self.process.birth},"source":{"device":original.dev(),"inode":original.ino(),"uid":original.uid(),"length":original.len()},"descriptor":descriptor,"syscall":number,"architecture":architecture,"read_bytes":count,"position":position,"fdinfo":fdinfo,"stopped_after_native_read":true}),
                );
            }
        }
        Err(CiError::Message(
            "original source read boundary was not reached within syscall bound".into(),
        ))
    }
    pub fn after_rename(
        &mut self,
        directory: &File,
        temporary: &str,
        final_name: &str,
        predicate: impl Fn(&[u8]) -> bool,
    ) -> Result<serde_json::Value> {
        self.after_rename_matching(directory, temporary, final_name, false, predicate)
    }
    pub fn after_rename_prefix(
        &mut self,
        directory: &File,
        prefix: &str,
        final_name: &str,
        predicate: impl Fn(&[u8]) -> bool,
    ) -> Result<serde_json::Value> {
        if prefix.is_empty()
            || Path::new(prefix).components().count() != 1
            || prefix.starts_with('.') && matches!(prefix, "." | "..")
        {
            return Err(CiError::Message(
                "native transaction prefix is not a direct nonempty filename prefix".into(),
            ));
        }
        self.after_rename_matching(directory, prefix, final_name, true, predicate)
    }
    fn after_rename_matching(
        &mut self,
        directory: &File,
        selector: &str,
        final_name: &str,
        prefix: bool,
        predicate: impl Fn(&[u8]) -> bool,
    ) -> Result<serde_json::Value> {
        let parent = directory.metadata()?;
        if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "syscall transaction directory custody differs".into(),
            ));
        }
        for _ in 0..4096 {
            let entry = self.next_syscall()?;
            if entry[0] != 1 || entry.len() < 80 {
                continue;
            }
            let architecture =
                u32::from_ne_bytes(entry[4..8].try_into().expect("bounded syscall info"));
            let number =
                u64::from_ne_bytes(entry[24..32].try_into().expect("bounded syscall info"));
            #[cfg(target_arch = "x86_64")]
            let selected = architecture == 0xc000003e && [82, 264, 316].contains(&number);
            #[cfg(target_arch = "aarch64")]
            let selected = architecture == 0xc00000b7 && [38, 276].contains(&number);
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            let selected = false;
            if !selected {
                continue;
            }
            let arguments: Vec<u64> = entry[32..80]
                .chunks_exact(8)
                .map(|chunk| u64::from_ne_bytes(chunk.try_into().expect("fixed register width")))
                .collect();
            let (source_address, target_address, source_fd, target_fd) =
                if architecture == 0xc000003e && number == 82 {
                    (
                        arguments[0],
                        arguments[1],
                        libc::AT_FDCWD as i64 as u64,
                        libc::AT_FDCWD as i64 as u64,
                    )
                } else {
                    (arguments[1], arguments[3], arguments[0], arguments[2])
                };
            let source = self.pathname(source_address)?;
            let temporary = std::str::from_utf8(&source)
                .map_err(|error| CiError::Message(error.to_string()))?;
            let selected_source = if prefix {
                Path::new(temporary)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(selector) && name.len() > selector.len())
            } else {
                source == selector.as_bytes()
            };
            if !selected_source || self.pathname(target_address)? != final_name.as_bytes() {
                continue;
            }
            for (path, descriptor) in [
                (Path::new(temporary), source_fd),
                (Path::new(final_name), target_fd),
            ] {
                if path.components().any(|part| {
                    !matches!(
                        part,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                }) {
                    return Err(CiError::Message(
                        "native transaction pathname is not normalized".into(),
                    ));
                }
                let held = if path.is_absolute() {
                    File::open(path.parent().ok_or_else(|| {
                        CiError::Message("absolute native transaction parent absent".into())
                    })?)?
                } else {
                    if path.components().count() != 1 {
                        return Err(CiError::Message(
                            "relative native transaction must be a direct held-directory leaf"
                                .into(),
                        ));
                    }
                    let descriptor = i32::try_from(descriptor as i64)
                        .map_err(|error| CiError::Message(error.to_string()))?;
                    File::open(if descriptor == libc::AT_FDCWD {
                        format!("/proc/{}/cwd", self.process.process_id)
                    } else {
                        format!("/proc/{}/fd/{descriptor}", self.process.process_id)
                    })?
                };
                let identity = held.metadata()?;
                if !identity.is_dir()
                    || (identity.dev(), identity.ino()) != (parent.dev(), parent.ino())
                {
                    return Err(CiError::Message(
                        "native rename uses another held transaction directory".into(),
                    ));
                }
            }
            let pending = rustix::fs::openat(
                directory,
                Path::new(temporary).file_name().ok_or_else(|| {
                    CiError::Message("native pending transaction leaf absent".into())
                })?,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(std::io::Error::from)?;
            let mut pending = File::from(pending);
            let identity = pending.metadata()?;
            if !identity.is_file()
                || identity.uid() != 0
                || identity.nlink() != 1
                || identity.mode() & 0o777 != 0o600
                || identity.len() > 512 * 1024
            {
                return Err(CiError::Message(
                    "pending native transaction record custody differs".into(),
                ));
            }
            let mut bytes = Vec::new();
            (&mut pending)
                .take(512 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if !predicate(&bytes) {
                continue;
            }
            let exit = self.next_syscall()?;
            if exit[0] != 2
                || exit.len() < 33
                || i64::from_ne_bytes(exit[24..32].try_into().expect("bounded syscall exit")) != 0
                || exit[32] != 0
            {
                return Err(CiError::Message(
                    "selected native rename did not succeed at its actual syscall exit".into(),
                ));
            }
            let published = rustix::fs::openat(
                directory,
                Path::new(final_name).file_name().ok_or_else(|| {
                    CiError::Message("native published transaction leaf absent".into())
                })?,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(std::io::Error::from)?;
            let mut published = File::from(published);
            let named = published.metadata()?;
            let mut actual = Vec::new();
            (&mut published)
                .take(512 * 1024 + 1)
                .read_to_end(&mut actual)?;
            if (identity.dev(), identity.ino()) != (named.dev(), named.ino())
                || bytes != actual
                || named.nlink() != 1
                || named.uid() != 0
                || named.mode() & 0o777 != 0o600
            {
                return Err(CiError::Message(
                    "published native transaction differs from the exact pending inode/bytes"
                        .into(),
                ));
            }
            return Ok(
                serde_json::json!({"mechanism":"ptrace-native-rename-exit","pid":self.process.process_id,"birth":self.process.birth,"architecture":architecture,"syscall":number,"source":temporary,"destination":final_name,"directory_device":parent.dev(),"directory_inode":parent.ino(),"device":named.dev(),"inode":named.ino(),"record_bytes":actual,"return_value":0,"worker_stopped_before_userspace":true}),
            );
        }
        Err(CiError::Message(
            "native transaction syscall inventory exceeds bound".into(),
        ))
    }
    pub fn detach(&mut self) -> Result<()> {
        if !self.attached {
            return Ok(());
        }
        if self.process.exited().map_err(CiError::Message)? {
            let mut status = 0;
            // SAFETY: this consumes only a pending debugger notification for
            // the process seized by this owner, never the frontend Child wait.
            let _ = unsafe {
                libc::waitpid(
                    self.process.process_id as i32,
                    &mut status,
                    libc::__WALL | libc::WNOHANG,
                )
            };
            self.attached = false;
            return Ok(());
        }
        if !self.stopped {
            self.control(libc::PTRACE_INTERRUPT, 0, 0)?;
            self.wait_stop()?;
        }
        if let Err(primary) = self.control(libc::PTRACE_DETACH, 0, 0) {
            while Instant::now() < self.cutoff {
                let mut status = 0;
                // SAFETY: PTRACE_SEIZE established this exact debugger owner.
                let observed = unsafe {
                    libc::waitpid(
                        self.process.process_id as i32,
                        &mut status,
                        libc::__WALL | libc::WNOHANG,
                    )
                };
                if observed == self.process.process_id as i32
                    && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
                {
                    self.attached = false;
                    self.stopped = false;
                    return Ok(());
                }
                if observed < 0 {
                    if self.process.exited().map_err(CiError::Message)? {
                        self.attached = false;
                        self.stopped = false;
                        return Ok(());
                    }
                    return Err(primary);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            return Err(primary);
        }
        self.attached = false;
        self.stopped = false;
        Ok(())
    }

    /// For an original Child whose supervisor has not started waiting yet:
    /// retain the exact post-syscall boundary as an ordinary kernel group stop,
    /// detach the debugger, and leave its sole exit wait with that supervisor.
    pub fn detach_stopped(&mut self) -> Result<serde_json::Value> {
        if !self.attached || !self.stopped || self.process.exited().map_err(CiError::Message)? {
            return Err(CiError::Message(
                "original debugger does not hold a live syscall stop".into(),
            ));
        }
        self.control(libc::PTRACE_DETACH, 0, libc::SIGSTOP as usize)?;
        self.attached = false;
        self.stopped = false;
        self.process
            .observe_stopped_until(self.cutoff)
            .map_err(CiError::Message)?;
        Ok(
            serde_json::json!({"pid":self.process.process_id,"birth":self.process.birth,"ptrace_detached":true,"signal":libc::SIGSTOP,"native_group_stop_observed":true,"exit_wait_consumed":false}),
        )
    }
}
impl Drop for NativeTraceStop {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

pub struct NativeNamespaceWatch {
    events: File,
    roots: Vec<(String, std::path::PathBuf, File, i32)>,
}
impl NativeNamespaceWatch {
    pub fn new(roots: &[(&str, &Path)]) -> Result<Self> {
        // SAFETY: fixed flags request a new, nonblocking kernel event FD.
        let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if raw < 0 {
            return Err(CiError::Message(format!(
                "native namespace observation unavailable: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: inotify_init1 transferred this fresh descriptor exactly once.
        let events = unsafe { File::from_raw_fd(raw) };
        let mut held = Vec::new();
        for (role, path) in roots {
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            let metadata = directory.metadata()?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(CiError::Message(
                    "native namespace observation directory is unprotected".into(),
                ));
            }
            let name = std::ffi::CString::new(format!("/proc/self/fd/{}", directory.as_raw_fd()))
                .expect("numeric held directory path");
            // SAFETY: the held directory FD pins this path for the call.
            let watch = unsafe {
                libc::inotify_add_watch(
                    events.as_raw_fd(),
                    name.as_ptr(),
                    libc::IN_CREATE
                        | libc::IN_MOVED_TO
                        | libc::IN_DELETE
                        | libc::IN_MOVED_FROM
                        | libc::IN_DELETE_SELF
                        | libc::IN_MOVE_SELF
                        | libc::IN_ONLYDIR,
                )
            };
            if watch < 0 {
                return Err(CiError::Message(format!(
                    "native namespace watch unavailable: {}",
                    std::io::Error::last_os_error()
                )));
            }
            held.push(((*role).into(), (*path).to_path_buf(), directory, watch));
        }
        Ok(Self {
            events,
            roots: held,
        })
    }
    pub fn snapshot(&self) -> Result<serde_json::Value> {
        use std::os::unix::ffi::OsStrExt;
        let mut observed = Vec::new();
        for (role, path, directory, _) in &self.roots {
            let metadata = directory.metadata()?;
            let root = std::path::PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
            let mut entries = Vec::new();
            for entry in std::fs::read_dir(&root)? {
                let entry = entry?;
                let name = entry.file_name();
                if role == "root-staging" && !name.as_bytes().starts_with(b"private-root-") {
                    continue;
                }
                if entries.len() >= 1024 {
                    return Err(CiError::Message(
                        "native namespace entry inventory exceeds bound".into(),
                    ));
                }
                let identity = std::fs::symlink_metadata(root.join(&name))?;
                entries.push(serde_json::json!({"name":name.as_bytes(),"device":identity.dev(),"inode":identity.ino(),"uid":identity.uid(),"mode":identity.mode(),"length":identity.len()}));
            }
            entries.sort_by(|left, right| left["name"].to_string().cmp(&right["name"].to_string()));
            observed.push(serde_json::json!({"role":role,"path":path,"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"mode":metadata.mode(),"entries":entries}));
        }
        Ok(serde_json::Value::Array(observed))
    }
    pub fn drain(&self) -> Result<serde_json::Value> {
        let mut buffer = [0u8; 65536];
        let mut observed = Vec::new();
        loop {
            let mut source = &self.events;
            let count = match source.read(&mut buffer) {
                Ok(0) => return Err(CiError::Message("native namespace observer closed".into())),
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            };
            let mut offset = 0;
            while offset < count {
                if count - offset < 16 {
                    return Err(CiError::Message("native namespace event truncated".into()));
                }
                let watch = i32::from_ne_bytes(
                    buffer[offset..offset + 4]
                        .try_into()
                        .expect("bounded watch header"),
                );
                let mask = u32::from_ne_bytes(
                    buffer[offset + 4..offset + 8]
                        .try_into()
                        .expect("bounded watch header"),
                );
                let length = u32::from_ne_bytes(
                    buffer[offset + 12..offset + 16]
                        .try_into()
                        .expect("bounded watch header"),
                ) as usize;
                if length > count - offset - 16 || mask & libc::IN_Q_OVERFLOW != 0 {
                    return Err(CiError::Message(
                        "native namespace event overflow or extent invalid".into(),
                    ));
                }
                let name = &buffer[offset + 16..offset + 16 + length];
                let name = &name[..name
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(name.len())];
                offset += 16 + length;
                let (role, _, _, _) = self
                    .roots
                    .iter()
                    .find(|(_, _, _, id)| *id == watch)
                    .ok_or_else(|| {
                        CiError::Message("native namespace event belongs to another watch".into())
                    })?;
                if role == "root-staging"
                    && !name.starts_with(b"private-root-")
                    && mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) == 0
                {
                    continue;
                }
                if observed.len() >= 4096 {
                    return Err(CiError::Message(
                        "native namespace event inventory exceeds bound".into(),
                    ));
                }
                observed.push(serde_json::json!({"role":role,"mask":mask,"name":name}));
            }
        }
        Ok(serde_json::Value::Array(observed))
    }
}
