//! Recovery adopts only freshly held native objects joined to durable ownership.
//! A recovered cleanup never reconstructs execution or successful output facts.
use super::private_attempt::{MixedDirectoryIdentityV2, PrivateAttemptRecordV4, ProcessIdentityV4};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

struct HeldProcess {
    identity: ProcessIdentityV4,
    fd: OwnedFd,
}
impl HeldProcess {
    fn acquire(identity: &ProcessIdentityV4) -> Result<Option<Self>, String> {
        let pid = i32::try_from(identity.pid).map_err(|_| "recovery PID exceeds native range")?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(None);
            }
            return Err(error.to_string());
        }
        let held = Self {
            identity: identity.clone(),
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
        };
        if held.exited()? {
            return Ok(None);
        }
        let birth = super::envelope::process_start_time(pid)?;
        if birth > identity.start_time {
            return Ok(None);
        }
        if birth != identity.start_time {
            return Err("recovery process birth differs".into());
        }
        if held.exited()? {
            return Ok(None);
        }
        Ok(Some(held))
    }
    fn exited(&self) -> Result<bool, String> {
        let mut descriptor = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let count = unsafe { libc::poll(&raw mut descriptor, 1, 0) };
        if count < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if descriptor.revents & !(libc::POLLIN | libc::POLLHUP) != 0 {
            return Err("recovery pidfd poll failed".into());
        }
        Ok(count > 0)
    }
    fn terminate(&self) -> Result<(), String> {
        if self.exited()? {
            return Ok(());
        }
        if super::envelope::process_start_time(self.identity.pid as i32)?
            != self.identity.start_time
        {
            return Err("recovery guardian identity drift".into());
        }
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                libc::SIGTERM,
                0,
                0,
            )
        } < 0
        {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.to_string());
            }
        }
        Ok(())
    }
}

fn directory(path: &Path, identity: &MixedDirectoryIdentityV2) -> Result<Option<File>, String> {
    let held = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(held) => held,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = held.metadata().map_err(|error| error.to_string())?;
    if metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || (metadata.dev(), metadata.ino()) != (identity.device, identity.inode)
    {
        return Err("recovery native directory identity differs".into());
    }
    Ok(Some(held))
}

fn unallocated_directory_absent(path: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    if !path.is_absolute() {
        return Err("recovery allocation intent is not absolute".into());
    }
    let mut parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|error| error.to_string())?;
    let components = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::RootDir => None,
            std::path::Component::Normal(value) => Some(Ok(value)),
            _ => Some(Err("recovery allocation intent is not normalized")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (name, ancestors) = components
        .split_last()
        .ok_or("recovery allocation intent has no filename")?;
    for component in ancestors {
        let name = std::ffi::CString::new(component.as_bytes())
            .map_err(|_| "recovery ancestor contains NUL")?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        parent = unsafe { File::from_raw_fd(fd) };
        let metadata = parent.metadata().map_err(|error| error.to_string())?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("recovery intent ancestry is not protected".into());
        }
    }
    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| "recovery intent filename contains NUL")?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Err("unobserved recovery allocation is present".into());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ENOENT) {
        return Err(error.to_string());
    }
    parent.sync_all().map_err(|error| error.to_string())
}

/// Settle the kernel family and private filesystem allocations. The caller
/// retains the journal/account/reference until its remaining owners are settled.
pub(super) fn settle_native(
    record: &PrivateAttemptRecordV4,
    cgroup_root: &Path,
    output_files: &[memcordon_core::workload_contract_v3::RootRelativePath],
) -> Result<(), String> {
    record.validate()?;
    if record.mixed_admission_metadata.is_none() {
        return Err("recovery lacks mixed ownership".into());
    }
    let boot =
        fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|error| error.to_string())?;
    let same_boot = record.boot_identity.as_str() == boot.trim();
    for owner in [Some(&record.frontend), record.mixed_worker.as_ref()]
        .into_iter()
        .flatten()
        .filter(|_| same_boot)
    {
        if HeldProcess::acquire(owner)?.is_some() {
            return Err("mixed recovery refuses a live native owner".into());
        }
    }
    let target = record
        .target
        .as_ref()
        .filter(|_| same_boot)
        .map(HeldProcess::acquire)
        .transpose()?
        .flatten();
    let init = record
        .namespace_init
        .as_ref()
        .filter(|_| same_boot)
        .map(HeldProcess::acquire)
        .transpose()?
        .flatten();
    let guardian = record
        .guardian
        .as_ref()
        .filter(|_| same_boot)
        .map(HeldProcess::acquire)
        .transpose()?
        .flatten();
    let deadline = Instant::now() + Duration::from_secs(5);
    let path = cgroup_root.join(record.attempt_id.as_str());
    if !same_boot
        && !matches!(fs::symlink_metadata(&path),Err(error)if error.kind()==std::io::ErrorKind::NotFound)
    {
        return Err("prior-boot recovery refuses a present kernel boundary".into());
    }
    match &record.mixed_cgroup_identity {
        Some(identity) => {
            if let Some(held) = directory(&path, identity)? {
                retire_cgroup(&path, &held, identity, deadline)?;
            }
        }
        None => {
            if !matches!(fs::symlink_metadata(path),Err(error)if error.kind()==std::io::ErrorKind::NotFound)
            {
                return Err("mixed cgroup intent has no native identity".into());
            }
        }
    }
    if let Some(guardian) = &guardian {
        guardian.terminate()?;
    }
    for held in [target.as_ref(), init.as_ref(), guardian.as_ref()]
        .into_iter()
        .flatten()
    {
        while !held.exited()? {
            if Instant::now() >= deadline {
                return Err("mixed recovery family remains live".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    if let Some(path) = &record.mixed_root_staging_intent {
        let path = Path::new(path.as_str());
        if let Some(identity) = record.mixed_staging_identity.as_ref() {
            if let Some(held) = directory(path, identity)? {
                if fs::read_dir(path)
                    .map_err(|error| error.to_string())?
                    .next()
                    .is_some()
                {
                    return Err(
                        "recovery staging still contains native mount or unknown entries".into(),
                    );
                }
                directory(path, identity)?.ok_or("held staging pathname disappeared")?;
                fs::remove_dir(path).map_err(|error| error.to_string())?;
                if held.metadata().map_err(|error| error.to_string())?.nlink() != 0 {
                    return Err("removed staging inode remains linked".into());
                }
            }
        } else {
            unallocated_directory_absent(path)?;
        }
        sync_parent(path)?;
    }
    if let Some(path) = &record.mixed_export_intent {
        let path = Path::new(path.as_str());
        if let Some(identity) = record.mixed_export_identity.as_ref() {
            if let Some(held) = directory(path, identity)? {
                let mut allowed = std::collections::BTreeSet::new();
                allowed.insert(std::path::PathBuf::from("export-receipt.json"));
                for file in output_files {
                    let mut item = Some(Path::new(file.as_str()));
                    while let Some(path) = item {
                        if path.as_os_str().is_empty() {
                            break;
                        }
                        allowed.insert(path.to_path_buf());
                        item = path.parent();
                    }
                }
                clear_exports(path, Path::new(""), &allowed, &mut 4096)?;
                held.sync_all().map_err(|error| error.to_string())?;
                directory(path, identity)?.ok_or("held export pathname disappeared")?;
                fs::remove_dir(path).map_err(|error| error.to_string())?;
                if held.metadata().map_err(|error| error.to_string())?.nlink() != 0 {
                    return Err("removed export inode remains linked".into());
                }
            }
        } else {
            unallocated_directory_absent(path)?;
        }
        sync_parent(path)?;
    }
    Ok(())
}
fn cgroup_control(root: &File, name: &str, write: bool) -> Result<File, String> {
    let name = std::ffi::CString::new(name).expect("fixed native control name");
    let flags = libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | if write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        };
    let raw = unsafe { libc::openat(root.as_raw_fd(), name.as_ptr(), flags) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}
fn retire_cgroup(
    path: &Path,
    held: &File,
    identity: &MixedDirectoryIdentityV2,
    deadline: Instant,
) -> Result<(), String> {
    cgroup_control(held, "cgroup.kill", true)?
        .write_all(b"1")
        .map_err(|error| error.to_string())?;
    loop {
        let mut events = String::new();
        cgroup_control(held, "cgroup.events", false)?
            .take(4097)
            .read_to_string(&mut events)
            .map_err(|error| error.to_string())?;
        if events.len() > 4096 {
            return Err("native cgroup events exceeded bound".into());
        }
        match events
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
        {
            Some("0") => {
                let mut members = String::new();
                cgroup_control(held, "cgroup.procs", false)?
                    .take(1024 * 1024 + 1)
                    .read_to_string(&mut members)
                    .map_err(|error| error.to_string())?;
                if !members.trim().is_empty() {
                    return Err("native recovered cgroup population disagrees".into());
                }
                directory(path, identity)?.ok_or("held recovered cgroup pathname disappeared")?;
                fs::remove_dir(path).map_err(|error| error.to_string())?;
                if held.metadata().map_err(|error| error.to_string())?.nlink() != 0 {
                    return Err("retired recovered cgroup inode remains linked".into());
                }
                return Ok(());
            }
            Some("1") => {}
            _ => return Err("native cgroup population field invalid".into()),
        }
        if Instant::now() >= deadline {
            return Err("native recovered cgroup remains populated".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn sync_parent(path: &Path) -> Result<(), String> {
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path.parent().ok_or("recovery parent absent")?)
        .map_err(|error| error.to_string())?;
    super::runtime_image::protected_directory(&parent)?;
    parent.sync_all().map_err(|error| error.to_string())
}
fn clear_exports(
    root: &Path,
    relative: &Path,
    allowed: &std::collections::BTreeSet<std::path::PathBuf>,
    remaining: &mut usize,
) -> Result<(), String> {
    for entry in fs::read_dir(root).map_err(|error| error.to_string())? {
        *remaining = remaining
            .checked_sub(1)
            .ok_or("recovery export entry limit exceeded")?;
        let entry = entry.map_err(|error| error.to_string())?;
        let member = relative.join(entry.file_name());
        if !allowed.contains(&member) {
            return Err("recovery export contains undeclared bytes".into());
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("recovery export custody differs".into());
        }
        if metadata.is_dir() {
            clear_exports(&entry.path(), &member, allowed, remaining)?;
            fs::remove_dir(entry.path()).map_err(|error| error.to_string())?;
        } else if metadata.is_file() && metadata.nlink() == 1 {
            fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
        } else {
            return Err("recovery export contains unsafe member".into());
        }
    }
    Ok(())
}
