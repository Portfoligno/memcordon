//! Scheduling observation only; the opened protected record remains authoritative.
#![allow(unsafe_code)]
use super::linux_current_phase_gate::{NativeTraceStop, namespace_identity, namespace_parent};
use crate::{CiError, Result};
use std::{
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
    time::Instant,
};

const ROOT: &str = "/var/lib/memcordon/workload-attempts";
pub struct JournalPublication {
    root: File,
    events: File,
    watch: i32,
    cutoff: Instant,
}
impl JournalPublication {
    pub fn new(cutoff: Instant) -> Result<Self> {
        let root = namespace_parent(Path::new(ROOT))
            .map_err(|error| error.context("copy protected journal root admission"))?;
        // SAFETY: fixed flags create a fresh nonblocking event descriptor.
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if raw < 0 {
            return Err(CiError::from(std::io::Error::last_os_error())
                .context("copy journal publication inotify initialization"));
        }
        // SAFETY: the fresh descriptor is transferred exactly once.
        let events = unsafe { File::from_raw_fd(raw) };
        let path = std::ffi::CString::new(format!("/proc/self/fd/{}", root.as_raw_fd()))
            .expect("numeric descriptor");
        // SAFETY: live pinned directory and NUL-terminated descriptor path.
        let watch = unsafe {
            libc::inotify_add_watch(
                events.as_raw_fd(),
                path.as_ptr(),
                libc::IN_CREATE
                    | libc::IN_MOVED_TO
                    | libc::IN_DELETE
                    | libc::IN_MOVED_FROM
                    | libc::IN_DELETE_SELF
                    | libc::IN_MOVE_SELF
                    | libc::IN_UNMOUNT
                    | libc::IN_ONLYDIR,
            )
        };
        if watch < 0 {
            return Err(CiError::from(std::io::Error::last_os_error())
                .context("copy journal publication watch installation"));
        }
        let result = Self {
            root,
            events,
            watch,
            cutoff,
        };
        result.revalidate()?;
        Ok(result)
    }
    pub fn revalidate(&self) -> Result<()> {
        if namespace_identity(&self.root)?
            != namespace_identity(&namespace_parent(Path::new(ROOT))?)?
        {
            return Err(CiError::Message(
                "copy protected journal root identity changed".into(),
            ));
        }
        Ok(())
    }
    pub fn wait_open(&self, name: &str, trace: &NativeTraceStop) -> Result<File> {
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CiError::Message(
                "copy journal attempt basename invalid".into(),
            ));
        }
        let mut count = 0usize;
        loop {
            if Instant::now() >= self.cutoff || trace.original_exited()? {
                return Err(CiError::Message(
                    "copy journal publication original cutoff/liveness exhausted".into(),
                ));
            }
            self.revalidate()?;
            let mut published = false;
            let mut bytes = [0u8; 65536];
            loop {
                let length = match (&self.events).read(&mut bytes) {
                    Ok(0) => {
                        return Err(CiError::Message(
                            "copy journal event observer closed".into(),
                        ));
                    }
                    Ok(n) => n,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        return Err(
                            CiError::from(error).context("copy journal publication event read")
                        );
                    }
                };
                let mut offset = 0;
                while offset < length {
                    if Instant::now() >= self.cutoff {
                        return Err(CiError::Message(
                            "copy journal event cutoff exhausted".into(),
                        ));
                    }
                    if length - offset < 16 {
                        return Err(CiError::Message("copy journal event truncated".into()));
                    }
                    let watch =
                        i32::from_ne_bytes(bytes[offset..offset + 4].try_into().expect("header"));
                    let mask = u32::from_ne_bytes(
                        bytes[offset + 4..offset + 8].try_into().expect("header"),
                    );
                    let size = u32::from_ne_bytes(
                        bytes[offset + 12..offset + 16].try_into().expect("header"),
                    ) as usize;
                    if size > length - offset - 16 {
                        return Err(CiError::Message("copy journal event extent invalid".into()));
                    }
                    let raw = &bytes[offset + 16..offset + 16 + size];
                    let basename =
                        &raw[..raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len())];
                    count += 1;
                    if count > 16384 {
                        return Err(CiError::Message(
                            "copy journal publication event bound exhausted".into(),
                        ));
                    }
                    published |= crate::snapshot_copy_contract::publication_event(
                        self.watch,
                        watch,
                        mask,
                        basename,
                        name.as_bytes(),
                    )?;
                    offset += 16 + size;
                }
            }
            if Instant::now() >= self.cutoff || trace.original_exited()? {
                return Err(CiError::Message(
                    "copy journal publication cutoff/liveness exhausted before exact open".into(),
                ));
            }
            let opened = rustix::fs::openat(
                &self.root,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::empty(),
            );
            match opened {
                Ok(file)=>{self.revalidate()?;return Ok(File::from(file));}
                Err(rustix::io::Errno::NOENT) if !published=>(),
                Err(error)=>return Err(CiError::from(std::io::Error::from(error)).context(format!("copy exact protected journal open root={ROOT} attempt={name} observed-publication={published}"))),
            }
            let remaining = self.cutoff.saturating_duration_since(Instant::now());
            let mut event = libc::pollfd {
                fd: self.events.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one live event descriptor; timeout never extends original cutoff.
            let ready = unsafe { libc::poll(&mut event, 1, remaining.as_millis().min(100) as i32) };
            if ready < 0 {
                return Err(CiError::from(std::io::Error::last_os_error())
                    .context("copy journal publication native wait"));
            }
            if event.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(CiError::Message(
                    "copy journal publication event descriptor failed".into(),
                ));
            }
        }
    }
}
