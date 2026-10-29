//! Cross-worker native intake slots and factual outstanding footprint charges.
//! Charge records survive worker loss; only observed allocation retirement removes them.
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub(super) const SLOT_COUNT: usize = 4;
pub(super) const RESOURCE_ROOT: &str = "/var/lib/memcordon/workload-resources";
pub(super) const SHARED_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) fn native_page_size() -> Result<u64, String> {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    u64::try_from(size)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "native page size unavailable".into())
}
pub(crate) fn rounded_bytes(bytes: u64, page: u64) -> Result<u64, String> {
    if page == 0 {
        return Err("native page size unavailable".into());
    }
    bytes
        .checked_add(page - 1)
        .map(|bytes| bytes / page * page)
        .ok_or_else(|| "native page rounding overflow".into())
}
pub(crate) fn writable_inode_limit(bytes: u64, page: u64) -> Result<u64, String> {
    rounded_bytes(bytes, page)?
        .checked_div(page)
        .and_then(|pages| pages.checked_add(64))
        .map(|count| count.min(65536))
        .ok_or_else(|| "writable inode budget overflow".into())
}
fn open_at(parent: &File, name: &str, flags: i32) -> Result<File, String> {
    let name = CString::new(name).map_err(|e| e.to_string())?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}
fn directory() -> Result<File, String> {
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/var/lib/memcordon")
        .map_err(|e| e.to_string())?;
    let metadata = parent.metadata().map_err(|e| e.to_string())?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("workload resource parent custody differs".into());
    }
    let name = c"workload-resources";
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let directory = open_at(
        &parent,
        "workload-resources",
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    let metadata = directory.metadata().map_err(|e| e.to_string())?;
    if metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("workload resource directory custody differs".into());
    }
    Ok(directory)
}
fn protected_file(file: &File) -> Result<(), String> {
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("workload resource file custody differs".into());
    }
    Ok(())
}
pub struct ReceiverSlot {
    _file: File,
}
pub enum ReceiverSlotError {
    CapacityUnavailable,
    Native(String),
}
impl From<String> for ReceiverSlotError {
    fn from(error: String) -> Self {
        Self::Native(error)
    }
}
impl ReceiverSlot {
    pub fn acquire() -> Result<Self, ReceiverSlotError> {
        let directory = directory()?;
        for index in 0..SLOT_COUNT {
            let name = std::path::Path::new("intake").with_extension(index.to_string());
            let name = name
                .to_str()
                .ok_or_else(|| "fixed intake name is not UTF-8".to_owned())?;
            let file = open_at(&directory, name, libc::O_RDWR | libc::O_CREAT)?;
            protected_file(&file)?;
            if file.metadata().map_err(|error| error.to_string())?.len() != 0 {
                return Err(ReceiverSlotError::Native(
                    "occupied intake slot has unexpected contents".into(),
                ));
            }
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self { _file: file });
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(ReceiverSlotError::Native(
                    std::io::Error::last_os_error().to_string(),
                ));
            }
        }
        Err(ReceiverSlotError::CapacityUnavailable)
    }
}

pub struct FootprintReservation {
    directory: File,
    name: CString,
    charge: File,
    allocator_lock: Option<File>,
    reserved_bytes: u64,
}
pub(crate) fn anonymous_charge(directory: &File) -> Result<File, String> {
    open_at(directory, ".", libc::O_RDWR | libc::O_TMPFILE)
}
pub(crate) fn publish_anonymous_charge(
    directory: &File,
    charge: &mut File,
    name: &std::ffi::CStr,
    bytes: u64,
) -> Result<(), String> {
    let metadata = charge.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.nlink() != 0 || metadata.len() != 0 {
        return Err("charge publication requires the original fresh anonymous file".into());
    }
    charge
        .write_all(&bytes.to_be_bytes())
        .and_then(|_| charge.sync_all())
        .map_err(|error| error.to_string())?;
    let source = std::path::Path::new("/proc/self/fd").join(charge.as_raw_fd().to_string());
    let source = CString::new(std::os::unix::ffi::OsStrExt::as_bytes(source.as_os_str()))
        .map_err(|error| error.to_string())?;
    // The pinned procfd link avoids CAP_DAC_READ_SEARCH, which the provider
    // does not possess. The actual anonymous file remains held throughout.
    if unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    directory.sync_all().map_err(|error| error.to_string())
}
impl FootprintReservation {
    pub fn acquire(attempt: &str, bytes: u64, available: u64) -> Result<Self, String> {
        if !super::cgroup::valid_attempt_identity(attempt) {
            return Err("invalid footprint attempt identity".into());
        }
        let directory = directory()?;
        let lock = open_at(&directory, "allocator.lock", libc::O_RDWR | libc::O_CREAT)?;
        protected_file(&lock)?;
        if lock.metadata().map_err(|error| error.to_string())?.len() != 0 {
            return Err("occupied footprint lock has unexpected contents".into());
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("workload footprint allocator temporarily unavailable".into());
        }
        let mut reserved = 0_u64;
        let held_path =
            std::path::Path::new("/proc/self/fd").join(directory.as_raw_fd().to_string());
        for entry in std::fs::read_dir(held_path).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name();
            let text = name.to_str().ok_or("non-UTF8 workload resource entry")?;
            if text == "allocator.lock"
                || text.strip_prefix("intake.").is_some_and(|n| {
                    n.parse::<usize>()
                        .is_ok_and(|index| index < SLOT_COUNT && text == format!("intake.{index}"))
                })
            {
                continue;
            }
            if !super::cgroup::valid_attempt_identity(text) {
                return Err("unknown workload resource allocation".into());
            }
            let mut file = open_at(&directory, text, libc::O_RDONLY)?;
            protected_file(&file)?;
            if file.metadata().map_err(|e| e.to_string())?.len()
                != u64::try_from(std::mem::size_of::<u64>()).expect("word length fits")
            {
                return Err("invalid footprint charge length".into());
            }
            let mut word = [0; std::mem::size_of::<u64>()];
            file.read_exact(&mut word).map_err(|e| e.to_string())?;
            reserved = reserved
                .checked_add(u64::from_be_bytes(word))
                .ok_or("outstanding footprint overflow")?;
        }
        if reserved
            .checked_add(bytes)
            .is_none_or(|total| total > available)
        {
            return Err("workload aggregate footprint unavailable".into());
        }
        let name = CString::new(attempt).map_err(|e| e.to_string())?;
        // The charge has no filesystem name until all eight bytes are durable.
        // A worker dying during publication cannot leave an empty named charge.
        let charge = anonymous_charge(&directory)?;
        Ok(Self {
            directory,
            name,
            charge,
            allocator_lock: Some(lock),
            reserved_bytes: bytes,
        })
    }
    /// The caller installs this owner in its failure ledger before any write.
    pub fn publish_charge(&mut self, bytes: u64) -> Result<(), String> {
        let metadata = self.charge.metadata().map_err(|error| error.to_string())?;
        if bytes != self.reserved_bytes
            || self.allocator_lock.is_none()
            || metadata.nlink() != 0
            || metadata.len() != 0
        {
            return Err("footprint publication is single-use under its allocator lock".into());
        }
        publish_anonymous_charge(&self.directory, &mut self.charge, &self.name, bytes)?;
        protected_file(&self.charge)?;
        self.directory.sync_all().map_err(|e| e.to_string())?;
        self.allocator_lock.take();
        Ok(())
    }
    /// Requires the actual owner to have observed all charged allocations absent.
    pub fn retire(self) -> Result<(), String> {
        let named = match open_at(
            &self.directory,
            self.name.to_str().map_err(|e| e.to_string())?,
            libc::O_RDONLY,
        ) {
            Ok(named) => named,
            Err(error) => {
                let path = std::path::Path::new("/proc/self/fd")
                    .join(self.directory.as_raw_fd().to_string())
                    .join(self.name.to_str().map_err(|cause| cause.to_string())?);
                if self
                    .charge
                    .metadata()
                    .map_err(|cause| cause.to_string())?
                    .nlink()
                    == 0
                    && matches!(std::fs::symlink_metadata(path),Err(cause) if cause.raw_os_error()==Some(libc::ENOENT))
                {
                    return Ok(());
                }
                return Err(error);
            }
        };
        protected_file(&named)?;
        let held = self.charge.metadata().map_err(|e| e.to_string())?;
        let current = named.metadata().map_err(|e| e.to_string())?;
        if (held.dev(), held.ino()) != (current.dev(), current.ino()) {
            return Err("footprint allocation inode changed".into());
        }
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        self.directory.sync_all().map_err(|e| e.to_string())
    }
}
